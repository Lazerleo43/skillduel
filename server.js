const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const app = express();
app.use(cors());
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

let openChallenges = [];
let activeMatches = {};

// Physics constants
const W = 340, H = 580;
const PL = 20, PR = W-20, PT = 44, PB = H-44;
const GTL = W/2-44, GBL = W/2+44, GW = 20;
const DISC_R = 18, BALL_R = 11;
const FRICTION = 0.985, WALL_B = 0.55;
const WIN = 3;

function createDiscs() {
  const cy = H/2;
  const bp = [
    {x:W/2,y:PB-80},{x:W/2-55,y:PB-140},{x:W/2+55,y:PB-140},
    {x:W/2-90,y:PB-210},{x:W/2+90,y:PB-210}
  ];
  const rp = [
    {x:W/2,y:PT+80},{x:W/2-55,y:PT+140},{x:W/2+55,y:PT+140},
    {x:W/2-90,y:PT+210},{x:W/2+90,y:PT+210}
  ];
  const discs = [];
  bp.forEach((p,i) => discs.push({x:p.x,y:p.y,vx:0,vy:0,r:DISC_R,team:0,id:i}));
  rp.forEach((p,i) => discs.push({x:p.x,y:p.y,vx:0,vy:0,r:DISC_R,team:1,id:i+5}));
  return discs;
}

function dist(a,b){ return Math.sqrt((a.x-b.x)**2+(a.y-b.y)**2); }

function resolveCol(a,b){
  const dx=b.x-a.x,dy=b.y-a.y,d=dist(a,b),mn=a.r+b.r;
  if(d<mn&&d>0){
    const nx=dx/d,ny=dy/d,ov=(mn-d)/2;
    a.x-=nx*ov;a.y-=ny*ov;b.x+=nx*ov;b.y+=ny*ov;
    const rv=(b.vx-a.vx)*nx+(b.vy-a.vy)*ny;
    if(rv<0){a.vx+=rv*0.85*nx;a.vy+=rv*0.85*ny;b.vx-=rv*0.85*nx;b.vy-=rv*0.85*ny;}
  }
}

function physicsStep(match) {
  const all = [...match.discs, match.ball];
  all.forEach(o => {
    o.x+=o.vx; o.y+=o.vy; o.vx*=FRICTION; o.vy*=FRICTION;
    if(Math.abs(o.vx)<0.02)o.vx=0; if(Math.abs(o.vy)<0.02)o.vy=0;
    if(o !== match.ball) {
      if(o.x-o.r<PL){o.x=PL+o.r;o.vx*=-WALL_B;}
      if(o.x+o.r>PR){o.x=PR-o.r;o.vx*=-WALL_B;}
      if(o.y-o.r<PT){o.y=PT+o.r;o.vy*=-WALL_B;}
      if(o.y+o.r>PB){o.y=PB-o.r;o.vy*=-WALL_B;}
    } else {
      const inTop = o.y-o.r<PT && o.x>GTL && o.x<GBL;
      const inBot = o.y+o.r>PB && o.x>GTL && o.x<GBL;
      if(o.x-o.r<PL){o.x=PL+o.r;o.vx*=-WALL_B;}
      if(o.x+o.r>PR){o.x=PR-o.r;o.vx*=-WALL_B;}
      if(!inTop){if(o.y-o.r<PT){o.y=PT+o.r;o.vy*=-WALL_B;}}
      if(!inBot){if(o.y+o.r>PB){o.y=PB-o.r;o.vy*=-WALL_B;}}
    }
  });
  for(let i=0;i<all.length;i++) for(let j=i+1;j<all.length;j++) resolveCol(all[i],all[j]);
}

function checkGoal(match) {
  const b = match.ball;
  if(b.y-b.r<PT-GW && b.x>GTL && b.x<GBL) return 0; // blue scores (top goal)
  if(b.y+b.r>PB+GW && b.x>GTL && b.x<GBL) return 1; // red scores (bottom goal)
  return -1;
}

function allStopped(match) {
  return ![...match.discs, match.ball].some(o => Math.abs(o.vx)>0.08 || Math.abs(o.vy)>0.08);
}

function resetBall(match) {
  match.ball = {x:W/2, y:H/2, vx:0, vy:0, r:BALL_R};
  match.discs.forEach(d => {d.vx=0; d.vy=0;});
}

function runMatchLoop(matchId) {
  const match = activeMatches[matchId];
  if(!match) return;

  match.wasStopped = false;

  match.interval = setInterval(() => {
    const m = activeMatches[matchId];
    if(!m) { clearInterval(match.interval); return; }
    if(m.goalCooldown > 0) { m.goalCooldown--; return; }

    physicsStep(m);

    // Check goals
    const scoringTeam = checkGoal(m);
    if(scoringTeam >= 0 && !m.goalCooldown) {
      m.score[scoringTeam]++;
      m.goalCooldown = 90;
      m.wasStopped = false;

      const concedingTeam = scoringTeam === 0 ? 1 : 0;
      m.turn = concedingTeam; // conceding team goes first

      io.to(m.player1).emit('goal_event', { score: m.score, scoringTeam });
      io.to(m.player2).emit('goal_event', { score: m.score, scoringTeam });

      setTimeout(() => {
        const mm = activeMatches[matchId];
        if(!mm) return;
        resetBall(mm);
        mm.goalCooldown = 0;
        mm.wasStopped = true;

        if(mm.score[0]>=WIN || mm.score[1]>=WIN) {
          io.to(mm.player1).emit('match_over_result', {score: mm.score});
          io.to(mm.player2).emit('match_over_result', {score: mm.score});
          clearInterval(mm.interval);
          delete activeMatches[matchId];
          return;
        }

        // Tell each player whose turn it is
        io.to(mm.player1).emit('ball_reset', {
          ball: mm.ball,
          score: mm.score,
          playerTurn: mm.turn === 0
        });
        io.to(mm.player2).emit('ball_reset', {
          ball: mm.ball,
          score: mm.score,
          playerTurn: mm.turn === 1
        });
      }, 1800);
    }

    // Detect when everything stops — switch turns
    const stopped = allStopped(m);
    if(stopped && !m.wasStopped && !m.goalCooldown) {
      m.wasStopped = true;
      // Switch turn to other player
      m.turn = m.turn === 0 ? 1 : 0;
      // Tell each player whose turn it is now
      io.to(m.player1).emit('your_turn', { playerTurn: m.turn === 0 });
      io.to(m.player2).emit('your_turn', { playerTurn: m.turn === 1 });
    } else if(!stopped) {
      m.wasStopped = false;
    }

    // Broadcast positions to both players every tick
    const state = {
      ball: m.ball,
      discs: m.discs.map(d=>({id:d.id,x:d.x,y:d.y,vx:d.vx,vy:d.vy}))
    };
    io.to(m.player1).emit('game_state', state);
    io.to(m.player2).emit('game_state', state);

  }, 1000/60);
}

io.on('connection', (socket) => {
  console.log('Ansluten:', socket.id);

  socket.on('get_challenges', () => { socket.emit('challenges_list', openChallenges); });

  socket.on('create_challenge', (data) => {
    openChallenges = openChallenges.filter(c => c.socketId !== socket.id);
    openChallenges.push({id:socket.id, name:data.name, stake:data.stake, socketId:socket.id});
    io.emit('challenges_list', openChallenges);
    io.emit('new_challenge', {name:data.name, stake:data.stake});
  });

  socket.on('cancel_challenge', () => {
    openChallenges = openChallenges.filter(c => c.socketId !== socket.id);
    io.emit('challenges_list', openChallenges);
  });

  socket.on('accept_challenge', (data) => {
    const challenge = openChallenges.find(c => c.id === data.challengeId);
    if(!challenge) return;
    openChallenges = openChallenges.filter(c => c.id !== data.challengeId);
    io.emit('challenges_list', openChallenges);

    const matchId = challenge.socketId + '_' + socket.id;
    const discs = createDiscs();
    activeMatches[matchId] = {
      player1: challenge.socketId,
      player2: socket.id,
      stake: challenge.stake,
      score: [0,0],
      ball: {x:W/2,y:H/2,vx:0,vy:0,r:BALL_R},
      discs,
      goalCooldown: 0,
      turn: 0 // 0=player1, 1=player2
    };

    io.to(challenge.socketId).emit('match_start', {matchId, role:'player1', opponent:data.name, stake:challenge.stake});
    io.to(socket.id).emit('match_start', {matchId, role:'player2', opponent:challenge.name, stake:challenge.stake});

    setTimeout(() => runMatchLoop(matchId), 500);
  });

  socket.on('player_move', (data) => {
    const match = activeMatches[data.matchId];
    if(!match) return;
    const disc = match.discs.find(d => d.id === data.discId);
    if(!disc) return;
    disc.vx = data.vx;
    disc.vy = data.vy;
  });

  socket.on('disconnect', () => {
    openChallenges = openChallenges.filter(c => c.socketId !== socket.id);
    io.emit('challenges_list', openChallenges);
    console.log('Frånkopplad:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => { console.log('Server koer paa port ' + PORT); });

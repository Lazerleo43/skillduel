const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.static('.'));
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
let openChallenges = [];
let activeMatches = {};

io.on('connection', (socket) => {
  console.log('Spelare ansluten:', socket.id);

  socket.on('get_challenges', () => {
    socket.emit('challenges_list', openChallenges);
  });

  socket.on('create_challenge', (data) => {
    openChallenges = openChallenges.filter(c => c.socketId !== socket.id);
    openChallenges.push({ id: socket.id, name: data.name, stake: data.stake, socketId: socket.id });
    io.emit('challenges_list', openChallenges);
    io.emit('new_challenge', { name: data.name, stake: data.stake });
  });

  socket.on('cancel_challenge', () => {
    openChallenges = openChallenges.filter(c => c.socketId !== socket.id);
    io.emit('challenges_list', openChallenges);
  });

  socket.on('accept_challenge', (data) => {
    const challenge = openChallenges.find(c => c.id === data.challengeId);
    if (!challenge) return;
    openChallenges = openChallenges.filter(c => c.id !== data.challengeId);
    io.emit('challenges_list', openChallenges);
    const matchId = challenge.socketId + '_' + socket.id;
    activeMatches[matchId] = {
      player1: challenge.socketId,
      player2: socket.id,
      stake: challenge.stake,
      score: [0, 0]
    };
    io.to(challenge.socketId).emit('match_start', {
      matchId, role: 'player1', opponent: data.name, stake: challenge.stake
    });
    io.to(socket.id).emit('match_start', {
      matchId, role: 'player2', opponent: challenge.name, stake: challenge.stake
    });
  });

  socket.on('game_move', (data) => {
    const match = activeMatches[data.matchId];
    if (!match) return;
    const opponent = match.player1 === socket.id ? match.player2 : match.player1;
    io.to(opponent).emit('opponent_move', data);
  });

  socket.on('goal_scored', (data) => {
    const match = activeMatches[data.matchId];
    if (!match) return;
    // Update score on server
    match.score[data.team]++;
    const opponent = match.player1 === socket.id ? match.player2 : match.player1;
    // Tell opponent a goal was scored and who scored
    io.to(opponent).emit('opponent_goal', {
      team: data.team,
      score: match.score
    });
    // Tell both players to reset ball to center
    // Conceding team (opposite of scoring) goes first after reset
    const concedingTeam = data.team === 0 ? 1 : 0;
    const p1GoesFirst = concedingTeam === 0;
    io.to(match.player1).emit('reset_after_goal', {
      score: match.score,
      playerTurn: p1GoesFirst
    });
    io.to(match.player2).emit('reset_after_goal', {
      score: match.score,
      playerTurn: !p1GoesFirst
    });
  });

  socket.on('match_over', (data) => {
    delete activeMatches[data.matchId];
  });

  socket.on('disconnect', () => {
    openChallenges = openChallenges.filter(c => c.socketId !== socket.id);
    io.emit('challenges_list', openChallenges);
    console.log('Spelare frånkopplad:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('SkillDuel server koer paa port ' + PORT);
});




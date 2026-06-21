const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const Stripe = require('stripe');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// ---------- DATABAS ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      display_name TEXT NOT NULL,
      balance_cents INTEGER NOT NULL DEFAULT 0,
      age_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      amount_cents INTEGER NOT NULL,
      stripe_session_id TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);
  console.log('Databas redo');
}

// ---------- LÖSENORDSHANTERING ----------
// PBKDF2 (inbyggt i Node, inget extra npm-paket behövs)
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
function genSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function verifyPassword(password, salt, hash) {
  const test = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(test, 'hex'), Buffer.from(hash, 'hex'));
}

// ---------- SESSIONS (enkel token-baserad auth) ----------
const sessions = {}; // token -> userId
function genToken() {
  return crypto.randomBytes(32).toString('hex');
}
async function getUserFromToken(token) {
  const userId = sessions[token];
  if (!userId) return null;
  const r = await pool.query('SELECT id, email, display_name, balance_cents, age_verified FROM users WHERE id=$1', [userId]);
  return r.rows[0] || null;
}
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Ej inloggad' });
  req.userId = sessions[token];
  req.token = token;
  next();
}

// ---------- STRIPE ----------
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;

// ============ API ROUTES ============

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Registrering
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;
    if (!email || !password || !displayName) return res.status(400).json({ error: 'Fyll i alla fält' });
    if (password.length < 6) return res.status(400).json({ error: 'Lösenordet måste vara minst 6 tecken' });
    const existing = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (existing.rows.length) return res.status(400).json({ error: 'E-postadressen används redan' });
    const salt = genSalt();
    const hash = hashPassword(password, salt);
    const r = await pool.query(
      'INSERT INTO users (email, password_hash, salt, display_name) VALUES ($1,$2,$3,$4) RETURNING id, email, display_name, balance_cents, age_verified',
      [email.toLowerCase(), hash, salt, displayName]
    );
    const user = r.rows[0];
    const token = genToken();
    sessions[token] = user.id;
    res.json({ token, user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Något gick fel' });
  }
});

// Inloggning
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Fyll i alla fält' });
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
    const user = r.rows[0];
    if (!user || !verifyPassword(password, user.salt, user.password_hash)) {
      return res.status(401).json({ error: 'Fel e-post eller lösenord' });
    }
    const token = genToken();
    sessions[token] = user.id;
    res.json({
      token,
      user: { id: user.id, email: user.email, display_name: user.display_name, balance_cents: user.balance_cents, age_verified: user.age_verified }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Något gick fel' });
  }
});

// Hämta egen profil/saldo
app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await getUserFromToken(req.token);
  if (!user) return res.status(401).json({ error: 'Ej inloggad' });
  res.json({ user });
});

// Logga ut
app.post('/api/logout', authMiddleware, (req, res) => {
  delete sessions[req.token];
  res.json({ ok: true });
});

// Skapa Stripe Checkout-session för insättning
app.post('/api/deposit/create-session', authMiddleware, async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Stripe ej konfigurerat' });
    const { amountKr } = req.body;
    const amount = parseInt(amountKr, 10);
    if (!amount || amount < 10 || amount > 5000) {
      return res.status(400).json({ error: 'Belopp måste vara mellan 10 och 5000 kr' });
    }
    const user = await getUserFromToken(req.token);
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'sek',
          product_data: { name: 'Insättning till SkillDuel-saldo' },
          unit_amount: amount * 100
        },
        quantity: 1
      }],
      success_url: `${req.headers.origin || 'https://skillduel.netlify.app'}/?deposit=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin || 'https://skillduel.netlify.app'}/?deposit=cancel`,
      metadata: { userId: String(user.id) }
    });
    await pool.query(
      'INSERT INTO transactions (user_id, type, amount_cents, stripe_session_id, status) VALUES ($1,$2,$3,$4,$5)',
      [user.id, 'deposit', amount * 100, session.id, 'pending']
    );
    res.json({ url: session.url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Kunde inte skapa betalning' });
  }
});

// Bekräfta insättning (anropas från klienten efter Stripe-redirect, dubbelkollas mot Stripe)
app.post('/api/deposit/confirm', authMiddleware, async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Stripe ej konfigurerat' });
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ error: 'Saknar sessionId' });

    const txCheck = await pool.query('SELECT * FROM transactions WHERE stripe_session_id=$1', [sessionId]);
    const tx = txCheck.rows[0];
    if (!tx) return res.status(404).json({ error: 'Transaktion hittades inte' });
    if (tx.status === 'completed') {
      const user = await getUserFromToken(req.token);
      return res.json({ ok: true, alreadyProcessed: true, user });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Betalningen är inte genomförd än' });
    }

    await pool.query('UPDATE transactions SET status=$1 WHERE stripe_session_id=$2', ['completed', sessionId]);
    await pool.query('UPDATE users SET balance_cents = balance_cents + $1 WHERE id=$2', [tx.amount_cents, tx.user_id]);

    const user = await getUserFromToken(req.token);
    res.json({ ok: true, user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Något gick fel vid bekräftelse' });
  }
});

// Transaktionshistorik
app.get('/api/transactions', authMiddleware, async (req, res) => {
  const r = await pool.query(
    'SELECT id, type, amount_cents, status, created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',
    [req.userId]
  );
  res.json({ transactions: r.rows });
});

// ============ SPELLOGIK (oförändrad fysik) ============

let openChallenges = [];
let activeMatches = {};
const W=340,H=580,PL=20,PR=320,PT=44,PB=536,GTL=126,GBL=214,GW=20,DISC_R=18,BALL_R=11,FRICTION=0.985,WALL_B=0.55,WIN=3;

function createDiscs(){const bp=[{x:170,y:456},{x:115,y:396},{x:225,y:396},{x:80,y:326},{x:260,y:326}];const rp=[{x:170,y:124},{x:115,y:184},{x:225,y:184},{x:80,y:254},{x:260,y:254}];const d=[];bp.forEach((p,i)=>d.push({x:p.x,y:p.y,vx:0,vy:0,r:DISC_R,team:0,id:i,startX:p.x,startY:p.y}));rp.forEach((p,i)=>d.push({x:p.x,y:p.y,vx:0,vy:0,r:DISC_R,team:1,id:i+5,startX:p.x,startY:p.y}));return d;}
function resetAfterGoal(m){m.ball={x:170,y:290,vx:0,vy:0,r:BALL_R};m.discs.forEach(d=>{d.x=d.startX;d.y=d.startY;d.vx=0;d.vy=0;});}
function dist(a,b){return Math.sqrt((a.x-b.x)**2+(a.y-b.y)**2);}
function resolveCol(a,b){const dx=b.x-a.x,dy=b.y-a.y,d=dist(a,b),mn=a.r+b.r;if(d<mn&&d>0){const nx=dx/d,ny=dy/d,ov=(mn-d)/2;a.x-=nx*ov;a.y-=ny*ov;b.x+=nx*ov;b.y+=ny*ov;const rv=(b.vx-a.vx)*nx+(b.vy-a.vy)*ny;if(rv<0){a.vx+=rv*0.85*nx;a.vy+=rv*0.85*ny;b.vx-=rv*0.85*nx;b.vy-=rv*0.85*ny;}}}
function physicsStep(m){const all=[...m.discs,m.ball];all.forEach(o=>{o.x+=o.vx;o.y+=o.vy;o.vx*=FRICTION;o.vy*=FRICTION;if(Math.abs(o.vx)<0.02)o.vx=0;if(Math.abs(o.vy)<0.02)o.vy=0;if(o!==m.ball){if(o.x-o.r<PL){o.x=PL+o.r;o.vx*=-WALL_B;}if(o.x+o.r>PR){o.x=PR-o.r;o.vx*=-WALL_B;}if(o.y-o.r<PT){o.y=PT+o.r;o.vy*=-WALL_B;}if(o.y+o.r>PB){o.y=PB-o.r;o.vy*=-WALL_B;}}else{const iT=o.y-o.r<PT&&o.x>GTL&&o.x<GBL;const iB=o.y+o.r>PB&&o.x>GTL&&o.x<GBL;if(o.x-o.r<PL){o.x=PL+o.r;o.vx*=-WALL_B;}if(o.x+o.r>PR){o.x=PR-o.r;o.vx*=-WALL_B;}if(!iT){if(o.y-o.r<PT){o.y=PT+o.r;o.vy*=-WALL_B;}}if(!iB){if(o.y+o.r>PB){o.y=PB-o.r;o.vy*=-WALL_B;}}}});for(let i=0;i<all.length;i++)for(let j=i+1;j<all.length;j++)resolveCol(all[i],all[j]);}
function checkGoal(m){const b=m.ball;if(b.y-b.r<PT-GW&&b.x>GTL&&b.x<GBL)return 0;if(b.y+b.r>PB+GW&&b.x>GTL&&b.x<GBL)return 1;return -1;}
function allStopped(m){return![...m.discs,m.ball].some(o=>Math.abs(o.vx)>0.08||Math.abs(o.vy)>0.08);}

function runMatchLoop(matchId){
  const m=activeMatches[matchId];if(!m)return;
  m.wasStopped=false;
  // Skydd mot dubbel-räkning av mål: en flagga som blockerar nya checkGoal-resultat under cooldown
  m.goalLock=false;
  m.interval=setInterval(()=>{
    const mm=activeMatches[matchId];if(!mm){clearInterval(m.interval);return;}
    if(mm.goalCooldown>0){mm.goalCooldown--;return;}
    physicsStep(mm);
    const st=checkGoal(mm);
    if(st>=0 && !mm.goalLock){
      mm.goalLock=true; // blockera direkt — bara EN gång per mål
      mm.score[st]++;
      mm.goalCooldown=90;
      mm.wasStopped=false;
      const ct=st===0?1:0;
      mm.turn=ct;
      io.to(mm.player1).emit('goal_event',{score:mm.score,scoringTeam:st,playerTurn: mm.player1Team===ct});
      io.to(mm.player2).emit('goal_event',{score:mm.score,scoringTeam:st,playerTurn: mm.player2Team===ct});
      setTimeout(()=>{
        const mmm=activeMatches[matchId];if(!mmm)return;
        resetAfterGoal(mmm);
        mmm.goalCooldown=0;
        mmm.wasStopped=true;
        mmm.goalLock=false; // redo för nästa mål
        if(mmm.score[0]>=WIN||mmm.score[1]>=WIN){
          settleMatch(matchId, mmm).catch(console.error);
          return;
        }
        io.to(mmm.player1).emit('ball_reset',{ball:mmm.ball,score:mmm.score,playerTurn:mmm.turn===mmm.player1Team,discs:mmm.discs.map(d=>({id:d.id,x:d.x,y:d.y}))});
        io.to(mmm.player2).emit('ball_reset',{ball:mmm.ball,score:mmm.score,playerTurn:mmm.turn===mmm.player2Team,discs:mmm.discs.map(d=>({id:d.id,x:d.x,y:d.y}))});
      },1800);
    }
    const stopped=allStopped(mm);
    if(stopped&&!mm.wasStopped&&!mm.goalCooldown){
      mm.wasStopped=true;
      mm.turn=mm.turn===0?1:0;
      io.to(mm.player1).emit('your_turn',{playerTurn:mm.turn===mm.player1Team});
      io.to(mm.player2).emit('your_turn',{playerTurn:mm.turn===mm.player2Team});
    }else if(!stopped){
      mm.wasStopped=false;
    }
    io.to(mm.player1).emit('game_state',{ball:mm.ball,discs:mm.discs.map(d=>({id:d.id,x:d.x,y:d.y,vx:d.vx,vy:d.vy}))});
    io.to(mm.player2).emit('game_state',{ball:mm.ball,discs:mm.discs.map(d=>({id:d.id,x:d.x,y:d.y,vx:d.vx,vy:d.vy}))});
  },1000/60);
}

// Avgör match: flytta pengar mellan spelarnas saldo i databasen
async function settleMatch(matchId, mm){
  clearInterval(mm.interval);
  const winnerTeam = mm.score[0] >= WIN ? 0 : 1;
  const winnerUserId = winnerTeam === mm.player1Team ? mm.player1UserId : mm.player2UserId;
  const loserUserId = winnerTeam === mm.player1Team ? mm.player2UserId : mm.player1UserId;
  const stakeCents = Math.round(mm.stake * 100);

  try {
    if (winnerUserId && loserUserId && stakeCents > 0) {
      // Vinnaren får båda insatserna (sin egen tillbaka + förlorarens)
      await pool.query('UPDATE users SET balance_cents = balance_cents + $1 WHERE id=$2', [stakeCents, winnerUserId]);
      await pool.query(
        'INSERT INTO transactions (user_id, type, amount_cents, status) VALUES ($1,$2,$3,$4)',
        [winnerUserId, 'match_win', stakeCents, 'completed']
      );
      await pool.query(
        'INSERT INTO transactions (user_id, type, amount_cents, status) VALUES ($1,$2,$3,$4)',
        [loserUserId, 'match_loss', -stakeCents, 'completed']
      );
    }
  } catch (e) {
    console.error('Fel vid avräkning av match:', e);
  }

  const p1User = mm.player1UserId ? await pool.query('SELECT balance_cents FROM users WHERE id=$1',[mm.player1UserId]) : null;
  const p2User = mm.player2UserId ? await pool.query('SELECT balance_cents FROM users WHERE id=$1',[mm.player2UserId]) : null;

  io.to(mm.player1).emit('match_over_result',{score:mm.score, newBalanceCents: p1User ? p1User.rows[0].balance_cents : null});
  io.to(mm.player2).emit('match_over_result',{score:mm.score, newBalanceCents: p2User ? p2User.rows[0].balance_cents : null});
  delete activeMatches[matchId];
}

io.on('connection',(socket)=>{
  console.log('Ansluten:',socket.id);

  socket.on('get_challenges',()=>{
    socket.emit('challenges_list',openChallenges);
  });

  socket.on('create_challenge',(data)=>{
    openChallenges=openChallenges.filter(c=>c.socketId!==socket.id);
    openChallenges.push({id:socket.id,name:data.name,stake:data.stake,socketId:socket.id,userId:data.userId});
    io.emit('challenges_list',openChallenges);
    io.emit('new_challenge',{name:data.name,stake:data.stake});
  });

  socket.on('cancel_challenge',()=>{
    openChallenges=openChallenges.filter(c=>c.socketId!==socket.id);
    io.emit('challenges_list',openChallenges);
  });

  socket.on('accept_challenge', async (data)=>{
    const challenge=openChallenges.find(c=>c.id===data.challengeId);
    if(!challenge)return;

    // Saldo-kontroll: båda spelarna måste ha tillräckligt med pengar för insatsen
    const stakeCents = Math.round(challenge.stake * 100);
    try {
      if (stakeCents > 0) {
        const p1 = await pool.query('SELECT balance_cents FROM users WHERE id=$1', [challenge.userId]);
        const p2 = await pool.query('SELECT balance_cents FROM users WHERE id=$1', [data.userId]);
        if (!p1.rows[0] || p1.rows[0].balance_cents < stakeCents) {
          socket.emit('challenge_error', { error: 'Utmanaren har inte tillräckligt med saldo längre' });
          openChallenges = openChallenges.filter(c => c.id !== data.challengeId);
          io.emit('challenges_list', openChallenges);
          return;
        }
        if (!p2.rows[0] || p2.rows[0].balance_cents < stakeCents) {
          socket.emit('challenge_error', { error: 'Du har inte tillräckligt med saldo för denna insats' });
          return;
        }
        // Lås insatserna: dra av direkt, återbetalas vid settleMatch till vinnaren
        await pool.query('UPDATE users SET balance_cents = balance_cents - $1 WHERE id=$2', [stakeCents, challenge.userId]);
        await pool.query('UPDATE users SET balance_cents = balance_cents - $1 WHERE id=$2', [stakeCents, data.userId]);
      }
    } catch (e) {
      console.error('Fel vid saldokontroll:', e);
      socket.emit('challenge_error', { error: 'Något gick fel, försök igen' });
      return;
    }

    openChallenges=openChallenges.filter(c=>c.id!==data.challengeId);
    io.emit('challenges_list',openChallenges);
    const matchId=challenge.socketId+'_'+socket.id;
    const discs=createDiscs();
    activeMatches[matchId]={
      player1:challenge.socketId,
      player2:socket.id,
      player1UserId: challenge.userId,
      player2UserId: data.userId,
      player1Team: 0,
      player2Team: 1,
      stake:challenge.stake,
      score:[0,0],
      ball:{x:170,y:290,vx:0,vy:0,r:BALL_R},
      discs,
      goalCooldown:0,
      turn:0,
      wasStopped:true
    };
    io.to(challenge.socketId).emit('match_start',{matchId,role:'player1',opponent:data.name,stake:challenge.stake});
    io.to(socket.id).emit('match_start',{matchId,role:'player2',opponent:challenge.name,stake:challenge.stake});
    setTimeout(()=>runMatchLoop(matchId),500);
  });

  socket.on('player_move',(data)=>{
    const match=activeMatches[data.matchId];
    if(!match)return;
    const disc=match.discs.find(d=>d.id===data.discId);
    if(!disc)return;
    disc.vx=data.vx;
    disc.vy=data.vy;
  });

  socket.on('disconnect',()=>{
    openChallenges=openChallenges.filter(c=>c.socketId!==socket.id);
    io.emit('challenges_list',openChallenges);
    console.log('Frånkopplad:',socket.id);
  });
});

const PORT = process.env.PORT || 3000;
initDb().then(() => {
  server.listen(PORT, () => { console.log('Server koer paa port ' + PORT); });
}).catch(err => {
  console.error('Kunde inte initiera databas:', err);
  // Starta servern även om DB-init misslyckas första gången (Postgres kan starta lite efter)
  server.listen(PORT, () => { console.log('Server koer paa port ' + PORT + ' (DB init fel — kollar igen)'); });
});

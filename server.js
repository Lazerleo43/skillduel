const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const Stripe = require('stripe');

const app = express();
app.use(cors());

// VIKTIGT: Stripe webhook-endpointen behöver RAW body INNAN express.json()
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    console.error('Webhook anropad men Stripe/webhook-secret är inte konfigurerat');
    return res.status(500).send('Webhook ej konfigurerat');
  }
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Ogiltig webhook-signatur:', err.message);
    return res.status(400).send('Ogiltig signatur');
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      if (session.payment_status === 'paid' && session.metadata && session.metadata.userId) {
        const userId = parseInt(session.metadata.userId, 10);
        const amountCents = session.amount_total;
        await creditDeposit(session.id, userId, amountCents);
      }
    }
  } catch (e) {
    console.error('Fel vid hantering av webhook-event:', e);
  }

  res.json({ received: true });
});

app.use(express.json());

// ---------- PAYPAL ----------
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
// Sätt till 'live' när PayPal godkänt kontot, 'sandbox' under testfas
const PAYPAL_MODE = process.env.PAYPAL_MODE || 'sandbox';
const PAYPAL_BASE = PAYPAL_MODE === 'live'
  ? 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com';

async function getPayPalAccessToken() {
  const res = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64')
    },
    body: 'grant_type=client_credentials'
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Kunde inte hämta PayPal access token');
  return data.access_token;
}

// Skapa PayPal-order för insättning
app.post('/api/paypal/create-order', authMiddleware, async (req, res) => {
  try {
    if (!PAYPAL_CLIENT_ID) return res.status(500).json({ error: 'PayPal ej konfigurerat' });
    const { amountKr } = req.body;
    const amount = parseInt(amountKr, 10);
    if (!amount || amount < 10 || amount > 5000) {
      return res.status(400).json({ error: 'Belopp måste vara mellan 10 och 5000 kr' });
    }
    const token = await getPayPalAccessToken();
    const orderRes = await fetch(`${PAYPAL_BASE}/v2/checkout/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: 'SEK',
            value: amount.toFixed(2)
          },
          description: `Insättning till Toosome-saldo — ${amount} kr`
        }],
        application_context: {
          brand_name: 'Toosome',
          landing_page: 'NO_PREFERENCE',
          user_action: 'PAY_NOW',
          return_url: `${process.env.APP_BASE_URL || 'https://toosome.com'}/?paypal=success`,
          cancel_url: `${process.env.APP_BASE_URL || 'https://toosome.com'}/?paypal=cancel`
        }
      })
    });
    const order = await orderRes.json();
    if (!orderRes.ok || !order.id) {
      console.error('PayPal create-order fel:', order);
      return res.status(500).json({ error: 'Kunde inte skapa PayPal-order' });
    }
    // Spara pending transaktion
    await pool.query(
      'INSERT INTO transactions (user_id, type, amount_cents, stripe_session_id, status) VALUES ($1,$2,$3,$4,$5)',
      [req.userId, 'deposit', amount * 100, `pp_${order.id}`, 'pending']
    );
    res.json({ orderId: order.id });
  } catch (e) {
    console.error('PayPal create-order error:', e);
    res.status(500).json({ error: 'Något gick fel' });
  }
});

// Bekräfta och capture:a PayPal-order efter att spelaren betalat
app.post('/api/paypal/capture-order', authMiddleware, async (req, res) => {
  try {
    if (!PAYPAL_CLIENT_ID) return res.status(500).json({ error: 'PayPal ej konfigurerat' });
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ error: 'Saknar orderId' });

    const token = await getPayPalAccessToken();
    const captureRes = await fetch(`${PAYPAL_BASE}/v2/checkout/orders/${orderId}/capture`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });
    const capture = await captureRes.json();

    if (!captureRes.ok || capture.status !== 'COMPLETED') {
      console.error('PayPal capture fel:', capture);
      return res.status(400).json({ error: 'Betalningen kunde inte bekräftas' });
    }

    // Kreditera saldot
    const amountStr = capture.purchase_units?.[0]?.payments?.captures?.[0]?.amount?.value;
    const amountCents = Math.round(parseFloat(amountStr) * 100);

    // Kontrollera att ordern tillhör denna användare
    const txCheck = await pool.query('SELECT * FROM transactions WHERE stripe_session_id=$1', [`pp_${orderId}`]);
    const tx = txCheck.rows[0];
    if (!tx || tx.user_id !== req.userId) {
      return res.status(403).json({ error: 'Order tillhör inte denna användare' });
    }
    if (tx.status === 'completed') {
      const user = await getUserFromToken(req.token);
      return res.json({ ok: true, alreadyProcessed: true, user });
    }

    await pool.query('UPDATE transactions SET status=$1 WHERE stripe_session_id=$2', ['completed', `pp_${orderId}`]);
    await pool.query('UPDATE users SET balance_cents = balance_cents + $1 WHERE id=$2', [amountCents, req.userId]);

    const user = await getUserFromToken(req.token);
    res.json({ ok: true, user });
  } catch (e) {
    console.error('PayPal capture error:', e);
    res.status(500).json({ error: 'Något gick fel' });
  }
});

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
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;`);
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
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_tx_stripe_session ON transactions(stripe_session_id) WHERE stripe_session_id IS NOT NULL;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS matches (
      id SERIAL PRIMARY KEY,
      match_id TEXT UNIQUE NOT NULL,
      player1_user_id INTEGER REFERENCES users(id),
      player2_user_id INTEGER REFERENCES users(id),
      player1_name TEXT,
      player2_name TEXT,
      stake_kr NUMERIC,
      rake_cents INTEGER NOT NULL DEFAULT 0,
      final_score_p1 INTEGER,
      final_score_p2 INTEGER,
      winner_user_id INTEGER REFERENCES users(id),
      events JSONB NOT NULL DEFAULT '[]',
      refunded BOOLEAN NOT NULL DEFAULT FALSE,
      started_at TIMESTAMP NOT NULL DEFAULT NOW(),
      ended_at TIMESTAMP
    );
  `);
  await pool.query(`ALTER TABLE matches ADD COLUMN IF NOT EXISTS rake_cents INTEGER NOT NULL DEFAULT 0;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS house_account (
      id INTEGER PRIMARY KEY DEFAULT 1,
      balance_cents BIGINT NOT NULL DEFAULT 0,
      CONSTRAINT single_row CHECK (id = 1)
    );
  `);
  await pool.query(`INSERT INTO house_account (id, balance_cents) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;`);

  // Uttags-begäranden från spelare
  await pool.query(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      amount_cents INTEGER NOT NULL,
      iban TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      completed_at TIMESTAMP
    );
  `);
  console.log('Databas redo');
}

// ---------- LÖSENORDSHANTERING ----------
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

// ---------- SESSIONS ----------
const sessions = {};
function genToken() {
  return crypto.randomBytes(32).toString('hex');
}
async function getUserFromToken(token) {
  const userId = sessions[token];
  if (!userId) return null;
  const r = await pool.query('SELECT id, email, display_name, balance_cents, age_verified, is_admin FROM users WHERE id=$1', [userId]);
  return r.rows[0] || null;
}
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Ej inloggad' });
  req.userId = sessions[token];
  req.token = token;
  next();
}
async function adminMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Ej inloggad' });
  const user = await getUserFromToken(token);
  if (!user || !user.is_admin) return res.status(403).json({ error: 'Endast administratörer har åtkomst' });
  req.userId = sessions[token];
  req.token = token;
  next();
}

// ---------- STRIPE ----------
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

async function creditDeposit(sessionId, userId, amountCents) {
  const txCheck = await pool.query('SELECT * FROM transactions WHERE stripe_session_id=$1', [sessionId]);
  const tx = txCheck.rows[0];
  if (!tx) {
    console.error('Webhook/confirm: okänd session_id:', sessionId);
    return { ok: false, error: 'Okänd transaktion' };
  }
  if (tx.status === 'completed') {
    return { ok: true, alreadyProcessed: true };
  }
  await pool.query('UPDATE transactions SET status=$1 WHERE stripe_session_id=$2', ['completed', sessionId]);
  await pool.query('UPDATE users SET balance_cents = balance_cents + $1 WHERE id=$2', [amountCents, userId]);
  return { ok: true, alreadyProcessed: false };
}

// ---------- BANKID ----------
const IDURA_DOMAIN = process.env.IDURA_DOMAIN;
const IDURA_CLIENT_ID = process.env.IDURA_CLIENT_ID;
const IDURA_CLIENT_SECRET = process.env.IDURA_CLIENT_SECRET;
const APP_BASE_URL = process.env.APP_BASE_URL || 'https://toosome.com';
const bankidStates = {};

function cleanupOldStates() {
  const now = Date.now();
  Object.keys(bankidStates).forEach(s => {
    if (now - bankidStates[s].createdAt > 10 * 60 * 1000) delete bankidStates[s];
  });
}

// ============ API ROUTES ============

app.get('/api/health', (req, res) => res.json({ ok: true }));

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

app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await getUserFromToken(req.token);
  if (!user) return res.status(401).json({ error: 'Ej inloggad' });
  res.json({ user });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  delete sessions[req.token];
  res.json({ ok: true });
});

// ---------- BANKID ----------
app.post('/api/bankid/start', authMiddleware, (req, res) => {
  if (!IDURA_DOMAIN || !IDURA_CLIENT_ID) {
    return res.status(500).json({ error: 'BankID-verifiering är inte konfigurerad ännu' });
  }
  cleanupOldStates();
  const state = crypto.randomBytes(24).toString('hex');
  bankidStates[state] = { userId: req.userId, createdAt: Date.now() };
  const redirectUri = `${APP_BASE_URL}/bankid-callback.html`;
  const authorizeUrl = `https://${IDURA_DOMAIN}/oauth2/authorize`
    + `?response_type=code`
    + `&client_id=${encodeURIComponent(IDURA_CLIENT_ID)}`
    + `&redirect_uri=${encodeURIComponent(redirectUri)}`
    + `&scope=${encodeURIComponent('openid is_over_18')}`
    + `&state=${encodeURIComponent(state)}`
    + `&acr_values=${encodeURIComponent('urn:grn:authn:se:bankid')}`;
  res.json({ url: authorizeUrl });
});

app.post('/api/bankid/callback', async (req, res) => {
  try {
    const { code, state } = req.body;
    if (!code || !state) return res.status(400).json({ error: 'Saknar code eller state' });
    const stateData = bankidStates[state];
    if (!stateData) return res.status(400).json({ error: 'Ogiltig eller utgången session — försök igen' });
    delete bankidStates[state];
    const tokenRes = await fetch(`https://${IDURA_DOMAIN}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${APP_BASE_URL}/bankid-callback.html`,
        client_id: IDURA_CLIENT_ID,
        client_secret: IDURA_CLIENT_SECRET
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok || !tokenData.id_token) {
      console.error('BankID token-fel:', tokenData);
      return res.status(400).json({ error: 'Kunde inte verifiera BankID-svaret' });
    }
    const payloadB64 = tokenData.id_token.split('.')[1];
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    const isOver18 = payload.is_over_18 === true || payload.is_over_18 === 'true';
    if (!isOver18) {
      return res.status(403).json({ error: 'Du måste vara 18 år eller äldre för att använda Toosome' });
    }
    await pool.query('UPDATE users SET age_verified=TRUE WHERE id=$1', [stateData.userId]);
    const user = (await pool.query('SELECT id, email, display_name, balance_cents, age_verified FROM users WHERE id=$1', [stateData.userId])).rows[0];
    res.json({ ok: true, user });
  } catch (e) {
    console.error('BankID callback-fel:', e);
    res.status(500).json({ error: 'Något gick fel vid åldersverifieringen' });
  }
});

// ---------- STRIPE INSÄTTNING ----------
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
          product_data: { name: 'Insättning till Toosome-saldo' },
          unit_amount: amount * 100
        },
        quantity: 1
      }],
      success_url: `${req.headers.origin || 'https://toosome.com'}/?deposit=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin || 'https://toosome.com'}/?deposit=cancel`,
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

app.post('/api/deposit/confirm', authMiddleware, async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Stripe ej konfigurerat' });
    const { sessionId } = req.body;
    if (!sessionId) return res.status(400).json({ error: 'Saknar sessionId' });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Betalningen är inte genomförd än' });
    }
    if (!session.metadata || parseInt(session.metadata.userId, 10) !== req.userId) {
      return res.status(403).json({ error: 'Sessionen tillhör inte denna användare' });
    }
    const result = await creditDeposit(sessionId, req.userId, session.amount_total);
    if (!result.ok) return res.status(404).json({ error: result.error });
    const user = await getUserFromToken(req.token);
    res.json({ ok: true, alreadyProcessed: !!result.alreadyProcessed, user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Något gick fel vid bekräftelse' });
  }
});

app.post('/api/admin/bootstrap', authMiddleware, async (req, res) => {
  try {
    const { secret } = req.body;
    if (!process.env.ADMIN_BOOTSTRAP_SECRET || secret !== process.env.ADMIN_BOOTSTRAP_SECRET) {
      return res.status(403).json({ error: 'Fel hemlig nyckel' });
    }
    await pool.query('UPDATE users SET is_admin=TRUE, age_verified=TRUE WHERE id=$1', [req.userId]);
    res.json({ ok: true, message: 'Ditt konto är nu admin och åldersverifierat' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Något gick fel' });
  }
});

app.get('/api/transactions', authMiddleware, async (req, res) => {
  const r = await pool.query(
    'SELECT id, type, amount_cents, status, created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',
    [req.userId]
  );
  res.json({ transactions: r.rows });
});

// ============ ADMIN ============

app.get('/api/admin/matches', adminMiddleware, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT match_id, player1_name, player2_name, stake_kr, rake_cents, final_score_p1, final_score_p2,
             winner_user_id, refunded, started_at, ended_at
      FROM matches ORDER BY started_at DESC LIMIT 200
    `);
    res.json({ matches: r.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Kunde inte hämta matcher' });
  }
});

app.get('/api/admin/matches/:matchId', adminMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM matches WHERE match_id=$1', [req.params.matchId]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Match hittades inte' });
    res.json({ match: r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Kunde inte hämta match' });
  }
});

app.get('/api/admin/house-balance', adminMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT balance_cents FROM house_account WHERE id=1');
    res.json({ balanceCents: r.rows[0] ? Number(r.rows[0].balance_cents) : 0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Kunde inte hämta husets saldo' });
  }
});

app.post('/api/admin/matches/:matchId/refund', adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'Saknar userId' });
    const matchR = await pool.query('SELECT * FROM matches WHERE match_id=$1', [req.params.matchId]);
    const match = matchR.rows[0];
    if (!match) return res.status(404).json({ error: 'Match hittades inte' });
    if (match.refunded) return res.status(400).json({ error: 'Denna match har redan återbetalats' });
    const stakeCents = Math.round(parseFloat(match.stake_kr) * 100);
    if (!stakeCents || stakeCents <= 0) return res.status(400).json({ error: 'Ogiltig insats för återbetalning' });
    await pool.query('UPDATE users SET balance_cents = balance_cents + $1 WHERE id=$2', [stakeCents, userId]);
    await pool.query(
      'INSERT INTO transactions (user_id, type, amount_cents, status) VALUES ($1,$2,$3,$4)',
      [userId, 'admin_refund', stakeCents, 'completed']
    );
    if (match.rake_cents > 0) {
      await pool.query('UPDATE house_account SET balance_cents = balance_cents - $1 WHERE id=1', [match.rake_cents]);
    }
    await pool.query('UPDATE matches SET refunded=TRUE WHERE match_id=$1', [req.params.matchId]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Kunde inte genomföra återbetalning' });
  }
});

// ---------- UTTAG ----------

// Spelare begär uttag — låser saldot och skapar en pending uttags-rad
app.post('/api/withdraw/request', authMiddleware, async (req, res) => {
  try {
    const { amountKr, iban } = req.body;
    const amount = parseInt(amountKr, 10);
    if (!amount || amount < 20) return res.status(400).json({ error: 'Minsta uttag är 20 kr' });
    if (!iban || !iban.toUpperCase().startsWith('SE') || iban.replace(/\s/g,'').length < 15) {
      return res.status(400).json({ error: 'Ogiltigt IBAN' });
    }
    const amountCents = amount * 100;

    // Kontrollera saldo
    const userR = await pool.query('SELECT balance_cents FROM users WHERE id=$1', [req.userId]);
    const user = userR.rows[0];
    if (!user || user.balance_cents < amountCents) {
      return res.status(400).json({ error: 'Otillräckligt saldo' });
    }

    // Dra av saldot direkt (låst tills admin hanterar det)
    await pool.query('UPDATE users SET balance_cents = balance_cents - $1 WHERE id=$2', [amountCents, req.userId]);

    // Spara uttags-begäran
    await pool.query(
      'INSERT INTO withdrawals (user_id, amount_cents, iban, status) VALUES ($1,$2,$3,$4)',
      [req.userId, amountCents, iban.replace(/\s/g,'').toUpperCase(), 'pending']
    );
    await pool.query(
      'INSERT INTO transactions (user_id, type, amount_cents, status) VALUES ($1,$2,$3,$4)',
      [req.userId, 'withdrawal_pending', -amountCents, 'pending']
    );

    const updatedUser = await getUserFromToken(req.token);
    res.json({ ok: true, user: updatedUser });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Något gick fel' });
  }
});

// Admin: lista alla uttags-begäranden
app.get('/api/admin/withdrawals', adminMiddleware, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT w.id, w.amount_cents, w.iban, w.status, w.created_at,
             u.display_name, u.email
      FROM withdrawals w
      JOIN users u ON u.id = w.user_id
      ORDER BY w.created_at DESC
      LIMIT 200
    `);
    res.json({ withdrawals: r.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Kunde inte hämta uttag' });
  }
});

// Admin: markera uttag som hanterat
app.post('/api/admin/withdrawals/:id/complete', adminMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM withdrawals WHERE id=$1', [req.params.id]);
    const w = r.rows[0];
    if (!w) return res.status(404).json({ error: 'Uttag hittades inte' });
    if (w.status === 'completed') return res.status(400).json({ error: 'Redan hanterat' });

    await pool.query('UPDATE withdrawals SET status=$1, completed_at=NOW() WHERE id=$2', ['completed', w.id]);
    await pool.query(
      'UPDATE transactions SET status=$1 WHERE user_id=$2 AND type=$3 AND status=$4',
      ['completed', w.user_id, 'withdrawal_pending', 'pending']
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Kunde inte markera som hanterat' });
  }
});

// Admin: avbryt uttag (återbetala saldot till spelaren)
app.post('/api/admin/withdrawals/:id/cancel', adminMiddleware, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM withdrawals WHERE id=$1', [req.params.id]);
    const w = r.rows[0];
    if (!w) return res.status(404).json({ error: 'Uttag hittades inte' });
    if (w.status !== 'pending') return res.status(400).json({ error: 'Kan bara avbryta pending uttag' });

    // Återbetala saldot
    await pool.query('UPDATE users SET balance_cents = balance_cents + $1 WHERE id=$2', [w.amount_cents, w.user_id]);
    await pool.query('UPDATE withdrawals SET status=$1 WHERE id=$2', ['cancelled', w.id]);
    await pool.query(
      'UPDATE transactions SET status=$1 WHERE user_id=$2 AND type=$3 AND status=$4',
      ['cancelled', w.user_id, 'withdrawal_pending', 'pending']
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Kunde inte avbryta uttag' });
  }
});

let openChallenges = [];
let activeMatches = {};
const W=340,H=580,PL=20,PR=320,PT=44,PB=536,GTL=126,GBL=214,GW=20,DISC_R=18,BALL_R=11,FRICTION=0.985,WALL_B=0.55,WIN=3;
const RAKE_PCT = 0.05;

function createDiscs(){const bp=[{x:170,y:456},{x:115,y:396},{x:225,y:396},{x:80,y:326},{x:260,y:326}];const rp=[{x:170,y:124},{x:115,y:184},{x:225,y:184},{x:80,y:254},{x:260,y:254}];const d=[];bp.forEach((p,i)=>d.push({x:p.x,y:p.y,vx:0,vy:0,r:DISC_R,team:0,id:i,startX:p.x,startY:p.y}));rp.forEach((p,i)=>d.push({x:p.x,y:p.y,vx:0,vy:0,r:DISC_R,team:1,id:i+5,startX:p.x,startY:p.y}));return d;}
function resetAfterGoal(m){m.ball={x:170,y:290,vx:0,vy:0,r:BALL_R};m.discs.forEach(d=>{d.x=d.startX;d.y=d.startY;d.vx=0;d.vy=0;});m.ballTouched=false;}
function dist(a,b){return Math.sqrt((a.x-b.x)**2+(a.y-b.y)**2);}
function resolveCol(a,b,m){const dx=b.x-a.x,dy=b.y-a.y,d=dist(a,b),mn=a.r+b.r;if(d<mn&&d>0){const nx=dx/d,ny=dy/d,ov=(mn-d)/2;a.x-=nx*ov;a.y-=ny*ov;b.x+=nx*ov;b.y+=ny*ov;const rv=(b.vx-a.vx)*nx+(b.vy-a.vy)*ny;if(rv<0){a.vx+=rv*0.85*nx;a.vy+=rv*0.85*ny;b.vx-=rv*0.85*nx;b.vy-=rv*0.85*ny;}if(m&&(a===m.ball||b===m.ball))m.ballTouched=true;}}
function physicsStep(m){const all=[...m.discs,m.ball];all.forEach(o=>{o.x+=o.vx;o.y+=o.vy;o.vx*=FRICTION;o.vy*=FRICTION;if(Math.abs(o.vx)<0.02)o.vx=0;if(Math.abs(o.vy)<0.02)o.vy=0;if(o!==m.ball){if(o.x-o.r<PL){o.x=PL+o.r;o.vx*=-WALL_B;}if(o.x+o.r>PR){o.x=PR-o.r;o.vx*=-WALL_B;}if(o.y-o.r<PT){o.y=PT+o.r;o.vy*=-WALL_B;}if(o.y+o.r>PB){o.y=PB-o.r;o.vy*=-WALL_B;}}else{const iT=o.y-o.r<PT&&o.x>GTL&&o.x<GBL;const iB=o.y+o.r>PB&&o.x>GTL&&o.x<GBL;if(o.x-o.r<PL){o.x=PL+o.r;o.vx*=-WALL_B;}if(o.x+o.r>PR){o.x=PR-o.r;o.vx*=-WALL_B;}if(!iT){if(o.y-o.r<PT){o.y=PT+o.r;o.vy*=-WALL_B;}}if(!iB){if(o.y+o.r>PB){o.y=PB-o.r;o.vy*=-WALL_B;}}}});for(let i=0;i<all.length;i++)for(let j=i+1;j<all.length;j++)resolveCol(all[i],all[j],m);}
function checkGoal(m){if(!m.ballTouched)return -1;const b=m.ball;if(b.y-b.r<PT-GW&&b.x>GTL&&b.x<GBL)return 0;if(b.y+b.r>PB+GW&&b.x>GTL&&b.x<GBL)return 1;return -1;}
function allStopped(m){return![...m.discs,m.ball].some(o=>Math.abs(o.vx)>0.08||Math.abs(o.vy)>0.08);}

function runMatchLoop(matchId){
  const m=activeMatches[matchId];if(!m)return;
  m.wasStopped=false;
  m.goalLock=false;
  m.turnTimer=0;       // räknar frames sedan senaste your_turn
  m.turnTimerActive=false;
  const TURN_FRAMES = 30 * 60; // 30 sekunder * 60fps

  m.interval=setInterval(()=>{
    const mm=activeMatches[matchId];if(!mm){clearInterval(m.interval);return;}
    if(mm.goalCooldown>0){mm.goalCooldown--;return;}
    physicsStep(mm);
    const st=checkGoal(mm);
    if(st>=0&&!mm.goalLock){
      mm.goalLock=true;
      mm.score[st]++;
      mm.goalCooldown=90;
      mm.wasStopped=false;
      mm.turnTimerActive=false; // stoppa timer vid mål
      const ct=st===0?1:0;
      mm.turn=ct;
      mm.events.push({t:Date.now()-mm.matchStartTime,type:'goal',scoringTeam:st,score:[...mm.score]});
      io.to(mm.player1).emit('goal_event',{score:mm.score,scoringTeam:st,playerTurn:mm.player1Team===ct});
      io.to(mm.player2).emit('goal_event',{score:mm.score,scoringTeam:st,playerTurn:mm.player2Team===ct});
      setTimeout(()=>{
        const mmm=activeMatches[matchId];if(!mmm)return;
        resetAfterGoal(mmm);
        mmm.goalCooldown=0;
        mmm.wasStopped=true;
        mmm.goalLock=false;
        if(mmm.score[0]>=WIN||mmm.score[1]>=WIN){
          settleMatch(matchId,mmm).catch(console.error);
          return;
        }
        io.to(mmm.player1).emit('ball_reset',{ball:mmm.ball,score:mmm.score,playerTurn:mmm.turn===mmm.player1Team,discs:mmm.discs.map(d=>({id:d.id,x:d.x,y:d.y}))});
        io.to(mmm.player2).emit('ball_reset',{ball:mmm.ball,score:mmm.score,playerTurn:mmm.turn===mmm.player2Team,discs:mmm.discs.map(d=>({id:d.id,x:d.x,y:d.y}))});
      },1800);
    }
    const stopped=allStopped(mm);
    if(stopped&&!mm.wasStopped&&!mm.goalCooldown){
      mm.wasStopped=true;
      mm.turnTimerActive=true;
      mm.turnTimer=0;
      mm.turn=mm.turn===0?1:0;
      io.to(mm.player1).emit('your_turn',{playerTurn:mm.turn===mm.player1Team});
      io.to(mm.player2).emit('your_turn',{playerTurn:mm.turn===mm.player2Team});
    }else if(!stopped){
      mm.wasStopped=false;
      mm.turnTimerActive=false;
      mm.turnTimer=0;
    }

    // Server-side turn-timer: om spelaren inte gör något drag inom 30s → timeout
    if(mm.turnTimerActive){
      mm.turnTimer++;
      if(mm.turnTimer >= TURN_FRAMES){
        mm.turnTimerActive=false;
        mm.turnTimer=0;
        // Räkna upp timeout-räknaren för den vars tur det är
        const loserTeam=mm.turn;
        const loserSocketId=loserTeam===mm.player1Team?mm.player1:mm.player2;
        if(!mm.timeoutCount) mm.timeoutCount={0:0,1:0};
        mm.timeoutCount[loserTeam]++;
        console.log(`Server timeout team ${loserTeam}: ${mm.timeoutCount[loserTeam]}`);
        if(mm.timeoutCount[loserTeam]>=2){
          // 2 timeouts → forfeit
          forfeitMatch(matchId,mm,loserSocketId,'timeout').catch(console.error);
          return;
        }
        // Annars avfyra slumpsten automatiskt och fortsätt
        const loserDiscs=mm.discs.filter(d=>d.team===loserTeam);
        if(loserDiscs.length){
          const d=loserDiscs[Math.floor(Math.random()*loserDiscs.length)];
          const angle=Math.random()*Math.PI*2;
          d.vx=Math.cos(angle)*4; d.vy=Math.sin(angle)*4;
          mm.events.push({t:Date.now()-mm.matchStartTime,type:'shot',discId:d.id,x:d.x,y:d.y,vx:d.vx,vy:d.vy});
        }
      }
    }

    io.to(mm.player1).emit('game_state',{ball:mm.ball,discs:mm.discs.map(d=>({id:d.id,x:d.x,y:d.y,vx:d.vx,vy:d.vy}))});
    io.to(mm.player2).emit('game_state',{ball:mm.ball,discs:mm.discs.map(d=>({id:d.id,x:d.x,y:d.y,vx:d.vx,vy:d.vy}))});
  },1000/60);
}

async function settleMatch(matchId,mm){
  clearInterval(mm.interval);
  const winnerTeam=mm.score[0]>=WIN?0:1;
  const winnerUserId=winnerTeam===mm.player1Team?mm.player1UserId:mm.player2UserId;
  const loserUserId=winnerTeam===mm.player1Team?mm.player2UserId:mm.player1UserId;
  const stakeCents=Math.round(mm.stake*100);
  const potCents=stakeCents*2;
  const rakeCents=Math.round(potCents*RAKE_PCT);
  const payoutCents=potCents-rakeCents;

  try {
    if(winnerUserId&&loserUserId&&stakeCents>0){
      await pool.query('UPDATE users SET balance_cents = balance_cents + $1 WHERE id=$2',[payoutCents,winnerUserId]);
      await pool.query('INSERT INTO transactions (user_id, type, amount_cents, status) VALUES ($1,$2,$3,$4)',[winnerUserId,'match_win',payoutCents,'completed']);
      await pool.query('INSERT INTO transactions (user_id, type, amount_cents, status) VALUES ($1,$2,$3,$4)',[loserUserId,'match_loss',-stakeCents,'completed']);
      await pool.query('UPDATE house_account SET balance_cents = balance_cents + $1 WHERE id=1',[rakeCents]);
    }
  } catch(e){
    console.error('Fel vid avräkning av match:',e);
  }

  const p1User=mm.player1UserId?await pool.query('SELECT balance_cents FROM users WHERE id=$1',[mm.player1UserId]):null;
  const p2User=mm.player2UserId?await pool.query('SELECT balance_cents FROM users WHERE id=$1',[mm.player2UserId]):null;

  io.to(mm.player1).emit('match_over_result',{score:mm.score,newBalanceCents:p1User?p1User.rows[0].balance_cents:null,rakeCents,payoutCents});
  io.to(mm.player2).emit('match_over_result',{score:mm.score,newBalanceCents:p2User?p2User.rows[0].balance_cents:null,rakeCents,payoutCents});

  try {
    await pool.query(
      `UPDATE matches SET final_score_p1=$1, final_score_p2=$2, winner_user_id=$3, events=$4, rake_cents=$5, ended_at=NOW() WHERE match_id=$6`,
      [mm.score[0],mm.score[1],winnerUserId||null,JSON.stringify(mm.events),rakeCents,matchId]
    );
  } catch(e){
    console.error('Kunde inte spara matchresultat:',e);
  }

  delete activeMatches[matchId];
}

// Forfeit: en spelare lämnar eller timeout:ar 2 gånger — motståndaren vinner hela potten
async function forfeitMatch(matchId, mm, loserSocketId, reason){
  if(!activeMatches[matchId]) return; // redan avgjord
  clearInterval(mm.interval);
  delete activeMatches[matchId];

  const isP1Loser = mm.player1 === loserSocketId;
  const winnerSocketId = isP1Loser ? mm.player2 : mm.player1;
  const winnerUserId = isP1Loser ? mm.player2UserId : mm.player1UserId;
  const loserUserId = isP1Loser ? mm.player1UserId : mm.player2UserId;
  const stakeCents = Math.round(mm.stake * 100);
  const potCents = stakeCents * 2;
  const rakeCents = Math.round(potCents * RAKE_PCT);
  const payoutCents = potCents - rakeCents;

  console.log(`Forfeit: match ${matchId}, reason: ${reason}, loser: ${loserSocketId}, winner: ${winnerSocketId}`);

  try {
    if(winnerUserId && stakeCents > 0){
      await pool.query('UPDATE users SET balance_cents = balance_cents + $1 WHERE id=$2',[payoutCents, winnerUserId]);
      await pool.query('INSERT INTO transactions (user_id, type, amount_cents, status) VALUES ($1,$2,$3,$4)',[winnerUserId,'match_win',payoutCents,'completed']);
      if(loserUserId){
        await pool.query('INSERT INTO transactions (user_id, type, amount_cents, status) VALUES ($1,$2,$3,$4)',[loserUserId,'match_loss',-stakeCents,'completed']);
      }
      await pool.query('UPDATE house_account SET balance_cents = balance_cents + $1 WHERE id=1',[rakeCents]);
    }
  } catch(e){ console.error('Fel vid forfeit-avräkning:',e); }

  const winnerBalR = winnerUserId ? await pool.query('SELECT balance_cents FROM users WHERE id=$1',[winnerUserId]) : null;
  const newBalanceCents = winnerBalR ? winnerBalR.rows[0].balance_cents : null;

  const winMsg = reason === 'timeout' ? 'Motståndaren spelade inte — du får walkover' :
                 reason === 'forfeit'  ? 'Motståndaren lämnade matchen' :
                 'Motståndaren kopplades bort';

  const lossMsg = reason === 'timeout' ? 'Du svarade inte i tid — motståndaren fick walkover' :
                  reason === 'forfeit' ? 'Du lämnade matchen' :
                  'Du kopplades bort';

  io.to(winnerSocketId).emit('match_forfeit_win', { reason: winMsg, payoutCents, newBalanceCents });
  io.to(loserSocketId).emit('match_forfeit_loss', { reason: lossMsg });

  try {
    await pool.query(
      `UPDATE matches SET final_score_p1=$1, final_score_p2=$2, winner_user_id=$3, rake_cents=$4, ended_at=NOW() WHERE match_id=$5`,
      [mm.score[0], mm.score[1], winnerUserId||null, rakeCents, matchId]
    );
  } catch(e){ console.error('Kunde inte spara forfeit:',e); }
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

  socket.on('accept_challenge',async(data)=>{
    const challenge=openChallenges.find(c=>c.id===data.challengeId);
    if(!challenge)return;
    const stakeCents=Math.round(challenge.stake*100);
    try {
      if(stakeCents>0){
        const p1=await pool.query('SELECT balance_cents FROM users WHERE id=$1',[challenge.userId]);
        const p2=await pool.query('SELECT balance_cents FROM users WHERE id=$1',[data.userId]);
        if(!p1.rows[0]||p1.rows[0].balance_cents<stakeCents){
          socket.emit('challenge_error',{error:'Utmanaren har inte tillräckligt med saldo längre'});
          openChallenges=openChallenges.filter(c=>c.id!==data.challengeId);
          io.emit('challenges_list',openChallenges);
          return;
        }
        if(!p2.rows[0]||p2.rows[0].balance_cents<stakeCents){
          socket.emit('challenge_error',{error:'Du har inte tillräckligt med saldo för denna insats'});
          return;
        }
        await pool.query('UPDATE users SET balance_cents = balance_cents - $1 WHERE id=$2',[stakeCents,challenge.userId]);
        await pool.query('UPDATE users SET balance_cents = balance_cents - $1 WHERE id=$2',[stakeCents,data.userId]);
      }
    } catch(e){
      console.error('Fel vid saldokontroll:',e);
      socket.emit('challenge_error',{error:'Något gick fel, försök igen'});
      return;
    }

    openChallenges=openChallenges.filter(c=>c.id!==data.challengeId);
    io.emit('challenges_list',openChallenges);
    const matchId=challenge.socketId+'_'+socket.id;
    const discs=createDiscs();
    activeMatches[matchId]={
      player1:challenge.socketId,player2:socket.id,
      player1UserId:challenge.userId,player2UserId:data.userId,
      player1Name:challenge.name,player2Name:data.name,
      player1Team:0,player2Team:1,
      stake:challenge.stake,score:[0,0],
      ball:{x:170,y:290,vx:0,vy:0,r:BALL_R},
      discs,goalCooldown:0,turn:0,wasStopped:true,
      ballTouched:false,events:[],matchStartTime:Date.now(),
      // Timeout-räknare: om en spelare låter tiden rinna ut 2 gånger i rad → förlust
      timeoutCount:{ 0:0, 1:0 }
    };
    io.to(challenge.socketId).emit('match_start',{matchId,role:'player1',opponent:data.name,stake:challenge.stake});
    io.to(socket.id).emit('match_start',{matchId,role:'player2',opponent:challenge.name,stake:challenge.stake});

    try {
      await pool.query(
        `INSERT INTO matches (match_id, player1_user_id, player2_user_id, player1_name, player2_name, stake_kr, events) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [matchId,challenge.userId,data.userId,challenge.name,data.name,challenge.stake,JSON.stringify([])]
      );
    } catch(e){
      console.error('Kunde inte spara match:',e);
    }

    setTimeout(()=>runMatchLoop(matchId),500);
  });

  socket.on('player_move',(data)=>{
    const match=activeMatches[data.matchId];
    if(!match)return;
    const disc=match.discs.find(d=>d.id===data.discId);
    if(!disc)return;
    disc.vx=data.vx;
    disc.vy=data.vy;
    // Nolla timeout-räknaren och turn-timern för spelaren som faktiskt sköt
    const team = match.player1===socket.id ? match.player1Team : match.player2Team;
    if(match.timeoutCount) match.timeoutCount[team]=0;
    match.turnTimerActive=false;
    match.turnTimer=0;
    match.events.push({t:Date.now()-match.matchStartTime,type:'shot',discId:data.discId,x:disc.x,y:disc.y,vx:data.vx,vy:data.vy});
  });

  // Klienten rapporterar timeout (30s-timern gick ut)
  // Om samma spelare timeout:ar 2 gånger i rad → förlust/forfeit
  socket.on('player_timeout',(data)=>{
    const match=activeMatches[data.matchId];
    if(!match) return;
    const isP1 = match.player1===socket.id;
    const myTeam = isP1 ? match.player1Team : match.player2Team;
    if(!match.timeoutCount) match.timeoutCount={0:0,1:0};
    match.timeoutCount[myTeam]++;
    console.log(`Timeout räknare team ${myTeam}: ${match.timeoutCount[myTeam]}`);
    if(match.timeoutCount[myTeam] >= 2){
      // 2 timeouts i rad → forfeit, motståndaren vinner
      const winnerSocketId = isP1 ? match.player2 : match.player1;
      forfeitMatch(data.matchId, match, socket.id, 'timeout').catch(console.error);
    }
  });

  // Spelaren klickar aktivt på "Lämna" → direkt forfeit
  socket.on('forfeit_match',(data)=>{
    const match=activeMatches[data.matchId];
    if(!match) return;
    forfeitMatch(data.matchId, match, socket.id, 'forfeit').catch(console.error);
  });

  socket.on('disconnect',()=>{
    openChallenges=openChallenges.filter(c=>c.socketId!==socket.id);
    io.emit('challenges_list',openChallenges);
    // Om spelaren kopplar bort mitt i match → forfeit
    Object.entries(activeMatches).forEach(([matchId, match])=>{
      if(match.player1===socket.id || match.player2===socket.id){
        forfeitMatch(matchId, match, socket.id, 'disconnect').catch(console.error);
      }
    });
    console.log('Frånkopplad:',socket.id);
  });
});

const PORT=process.env.PORT||3000;
initDb().then(()=>{
  server.listen(PORT,()=>{console.log('Server koer paa port '+PORT);});
}).catch(err=>{
  console.error('Kunde inte initiera databas:',err);
  server.listen(PORT,()=>{console.log('Server koer paa port '+PORT+' (DB init fel)');});
});

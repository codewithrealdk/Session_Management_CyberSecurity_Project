
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();
const PORT = 3001; 

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const messages = [];


// FIX for Finding #1 (predictable session IDs + hardcoded secret)
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function strongGenId(req) {
  return crypto.randomBytes(32).toString('hex');
}

// FIX for Finding #3 (broken logout) and #2 (session fixation),
const FIFTEEN_MIN = 15 * 60 * 1000;

const sessionStore = new FileStore({
  path: require('path').join(__dirname, 'sessions'),
  ttl: FIFTEEN_MIN / 1000, // seconds; store itself expires stale session files
  reapInterval: 60,        // clean up expired session files every 60s
  logFn: () => {}          // quiet; comment out while debugging if needed
});


app.use(session({
  genid: strongGenId,
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false, // FIX: don't create sessions for anonymous visitors
  rolling: true,            // sliding expiration: active users stay logged in, idle ones expire
  cookie: {
    // -----------------------------------------------------------------
    // FIX for Finding #4/#5 (insecure cookie attributes)
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: FIFTEEN_MIN
  }
}));

// -------------------- Routes --------------------

app.get('/', (req, res) => {
  res.redirect(req.session.user ? '/dashboard' : '/login');
});

app.get('/signup', (req, res) => res.render('signup', { error: null }));

app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render('signup', { error: 'Username and password required.' });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
    res.redirect('/login');
  } catch (e) {
    res.render('signup', { error: 'Username already taken.' });
  }
});

app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.render('login', { error: 'Invalid credentials.' });
  }


  // FIX for Finding #2 (session fixation)
  req.session.regenerate((err) => {
    if (err) return res.status(500).send('Session error.');
    req.session.user = { id: user.id, username: user.username };
    res.redirect('/dashboard');
  });
});

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', {
    user: req.session.user,
    sessionId: req.sessionID,
    messages
  });
});

app.post('/comment', requireLogin, (req, res) => {
  // FIX for Finding #6 (stored XSS): the view now uses EJS's escaped
  messages.push({ user: req.session.user.username, text: req.body.text });
  res.redirect('/dashboard');
});


// FIX for Finding #3 (broken logout)
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// Debug helper — kept ONLY for side-by-side testing
app.get('/whoami', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    session: req.session
  });
});

app.listen(PORT, () => {
  console.log(`Hardened session demo running at http://localhost:${PORT}`);
});

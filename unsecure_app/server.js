const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- In-memory "message board" used later for the cookie-theft/XSS demo ---
const messages = [];


// VULNERABILITY #1: Predictable session IDs
let sessionCounter = 1000;
function weakGenId(req) {
  sessionCounter += 1;
  return `sess_${sessionCounter}`;
}

app.use(session({
  genid: weakGenId,
  secret: 'super-secret-key', // hardcoded on purpose (bad practice, discuss in report)
  resave: false,
  saveUninitialized: true,
  // VULNERABILITY #2: Insecure cookie configuration
  cookie: {
    httpOnly: false,
    secure: false
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

  // VULNERABILITY #3: Session fixation
  req.session.user = { id: user.id, username: user.username };
  res.redirect('/dashboard');
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

// A tiny "leave a comment" board — intentionally renders input WITHOUT
// escaping, so it can be used to demonstrate stored XSS -> cookie theft
// in a controlled way (since httpOnly is disabled above).
app.post('/comment', requireLogin, (req, res) => {
  messages.push({ user: req.session.user.username, text: req.body.text });
  res.redirect('/dashboard');
});


// VULNERABILITY #4: Broken/incomplete logout
app.get('/logout', (req, res) => {
  res.clearCookie('connect.sid');
  res.redirect('/login');
});

// Debug helper endpoint — lets us show the raw session ID/cookie during the demo without needing devtools.
app.get('/whoami', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    session: req.session
  });
});

app.listen(PORT, () => {
  console.log(`Vulnerable session demo running at http://localhost:${PORT}`);
});

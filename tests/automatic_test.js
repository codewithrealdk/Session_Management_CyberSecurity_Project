const crypto = require('crypto');

const APPS = [
  { name: 'Vulnerable App', base: 'http://localhost:3000', knownSecret: 'super-secret-key' },
  { name: 'Hardened App', base: 'http://localhost:3001', knownSecret: 'super-secret-key' } // same guess attempted on both, on purpose
];

// -------------------- low-level helpers --------------------

// Minimal reimplementation of express-session's cookie-signing scheme
// (cookie-signature package), so this script has zero dependencies.
function signSessionId(val, secret) {
  const hmac = crypto.createHmac('sha256', secret).update(val).digest('base64').replace(/=+$/, '');
  return `s%3A${encodeURIComponent(`${val}.${hmac}`)}`;
}

function parseSetCookie(setCookieHeader) {
  if (!setCookieHeader) return null;
  const parts = setCookieHeader.split(';').map(p => p.trim());
  const [nameValue] = parts;
  const [name, value] = nameValue.split('=');
  const attrs = {
    httpOnly: /httponly/i.test(setCookieHeader),
    secure: /secure/i.test(setCookieHeader),
    sameSite: (setCookieHeader.match(/samesite=([^;]+)/i) || [,'(not set)'])[1],
    hasMaxAgeOrExpires: /max-age=|expires=/i.test(setCookieHeader)
  };
  return { name, value, raw: setCookieHeader, attrs };
}

async function request(base, path, { method = 'GET', body, cookie } = {}) {
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (cookie) headers['Cookie'] = cookie;
  const res = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body ? new URLSearchParams(body).toString() : undefined,
    redirect: 'manual'
  });
  const setCookie = res.headers.get('set-cookie');
  let json = null;
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    try { json = await res.json(); } catch (_) { /* ignore */ }
  }
  return { status: res.status, setCookie, json };
}

function cookieHeaderFromSetCookie(setCookieStr) {
  if (!setCookieStr) return null;
  return setCookieStr.split(';')[0];
}

// -------------------- individual checks --------------------

async function checkCookieFlags(base) {
  const username = `flags_${Date.now()}`;
  await request(base, '/signup', { method: 'POST', body: { username, password: 'password123' } });
  const loginRes = await request(base, '/login', { method: 'POST', body: { username, password: 'password123' } });
  const parsed = parseSetCookie(loginRes.setCookie);
  if (!parsed) return { vulnerable: true, evidence: 'No Set-Cookie header found.' };

  const problems = [];
  if (!parsed.attrs.httpOnly) problems.push('missing HttpOnly');
  if (!parsed.attrs.secure) problems.push('missing Secure (acceptable on localhost/dev)');
  if (!/strict/i.test(parsed.attrs.sameSite)) problems.push(`weak SameSite (${parsed.attrs.sameSite})`);
  if (!parsed.attrs.hasMaxAgeOrExpires) problems.push('no expiration set');

  // We don't fail purely on "Secure" since this suite runs over http://localhost.
  const hardProblems = problems.filter(p => !p.includes('acceptable on localhost'));
  return {
    vulnerable: hardProblems.length > 0,
    evidence: problems.length ? problems.join(', ') : 'HttpOnly, SameSite=Strict, and expiration all present.'
  };
}

function checkSessionIdFormat(sessionId) {
  if (!sessionId) return { vulnerable: null, evidence: 'Could not read a session ID.' };
  const sequential = /^sess_\d+$/.test(sessionId);
  return {
    vulnerable: sequential,
    evidence: sequential
      ? `ID "${sessionId}" is short and sequential — easy to enumerate.`
      : `ID "${sessionId}" (${sessionId.length} chars) looks like high-entropy random data.`
  };
}

async function establishBaseline(base) {
  const username = `baseline_${Date.now()}`;
  await request(base, '/signup', { method: 'POST', body: { username, password: 'password123' } });
  const loginRes = await request(base, '/login', { method: 'POST', body: { username, password: 'password123' } });
  const cookie = cookieHeaderFromSetCookie(loginRes.setCookie);
  const who = await request(base, '/whoami', { cookie });
  return { cookie, sessionId: who.json ? who.json.sessionID : null };
}

async function checkSecretForgery(base, knownSecret) {
  for (let i = 1000; i <= 1050; i++) {
    const id = `sess_${i}`;
    const cookie = `connect.sid=${signSessionId(id, knownSecret)}`;
    const res = await request(base, '/whoami', { cookie });
    if (res.json && res.json.session && res.json.session.user) {
      return { vulnerable: true, evidence: `Forged cookie for "${id}" was accepted as user "${res.json.session.user.username}".` };
    }
  }
  return { vulnerable: false, evidence: 'No forged cookie using the known/guessed secret was accepted.' };
}

async function checkSessionFixation(base) {
  const pre = await request(base, '/whoami');
  const preCookie = cookieHeaderFromSetCookie(pre.setCookie);
  const preId = pre.json ? pre.json.sessionID : null;
  if (!preCookie) {
    // No Set-Cookie before login at all (e.g. saveUninitialized: false) means
    // there is no pre-auth session cookie available to fixate in the first
    // place — classic fixation doesn't apply. That's a secure outcome.
    return { vulnerable: false, evidence: 'App does not issue a session cookie before login (saveUninitialized: false), so there is no pre-login session to fixate.' };
  }

  const username = `fixation_${Date.now()}`;
  await request(base, '/signup', { method: 'POST', body: { username, password: 'password123' } });
  const loginRes = await request(base, '/login', { method: 'POST', body: { username, password: 'password123' }, cookie: preCookie });
  const postCookie = cookieHeaderFromSetCookie(loginRes.setCookie) || preCookie;

  const post = await request(base, '/whoami', { cookie: postCookie });
  const postId = post.json ? post.json.sessionID : null;

  const unchanged = preId === postId;
  return {
    vulnerable: unchanged,
    evidence: unchanged
      ? `Session ID unchanged across login (${preId}).`
      : `Session ID changed on login (${preId} -> ${postId}).`
  };
}

async function checkBrokenLogout(base) {
  const username = `logout_${Date.now()}`;
  await request(base, '/signup', { method: 'POST', body: { username, password: 'password123' } });
  const loginRes = await request(base, '/login', { method: 'POST', body: { username, password: 'password123' } });
  const cookie = cookieHeaderFromSetCookie(loginRes.setCookie);
  if (!cookie) return { vulnerable: null, evidence: 'Login did not return a cookie.' };

  await request(base, '/logout', { cookie });
  const after = await request(base, '/dashboard', { cookie });

  const stillWorks = after.status === 200;
  return {
    vulnerable: stillWorks,
    evidence: stillWorks
      ? `Dashboard still returned HTTP 200 after logout using the old cookie.`
      : `Dashboard returned HTTP ${after.status} (access denied) after logout.`
  };
}

async function checkStoredXSS(base) {
  const username = `xss_${Date.now()}`;
  await request(base, '/signup', { method: 'POST', body: { username, password: 'password123' } });
  const loginRes = await request(base, '/login', { method: 'POST', body: { username, password: 'password123' } });
  const cookie = cookieHeaderFromSetCookie(loginRes.setCookie);
  const payload = `<script>alert('xss-test-${Date.now()}')</script>`;
  await request(base, '/comment', { method: 'POST', body: { text: payload }, cookie });

  const res = await fetch(`${base}/dashboard`, { headers: { Cookie: cookie } });
  const html = await res.text();
  const executable = html.includes(payload); // raw, unescaped
  return {
    vulnerable: executable,
    evidence: executable
      ? 'Payload found unescaped in the HTML — would execute in a browser.'
      : 'Payload was HTML-escaped — would render as inert text.'
  };
}

// -------------------- runner --------------------

function verdict(v) {
  if (v === null) return 'N/A';
  return v ? 'VULNERABLE' : 'SECURE';
}

async function runChecksForApp(app) {
  // Establish one baseline logged-in session FIRST, before anything else
  // runs — this guarantees there's a real active session for the secret-
  // forgery check to find within its guessed ID range.
  const baseline = await establishBaseline(app.base);

  const checks = [
    { name: 'Session ID format (guessable?)', run: () => checkSessionIdFormat(baseline.sessionId) },
    { name: 'Session ID forgeable w/ known secret', run: () => checkSecretForgery(app.base, app.knownSecret) },
    { name: 'Session fixation (ID unchanged on login)', run: () => checkSessionFixation(app.base) },
    { name: 'Broken logout (old cookie still works)', run: () => checkBrokenLogout(app.base) },
    { name: 'Stored XSS (unescaped output)', run: () => checkStoredXSS(app.base) },
    { name: 'Insecure cookie flags', run: () => checkCookieFlags(app.base) }
  ];

  const results = {};
  for (const check of checks) {
    try {
      results[check.name] = await check.run();
    } catch (err) {
      results[check.name] = { vulnerable: null, evidence: `Error: ${err.message}` };
    }
  }
  return results;
}

(async () => {
  console.log('Running Phase 4 comparative test suite...\n');
  const results = {}; // results[appName][checkName] = {vulnerable, evidence}
  const CHECK_NAMES = [
    'Session ID format (guessable?)',
    'Session ID forgeable w/ known secret',
    'Session fixation (ID unchanged on login)',
    'Broken logout (old cookie still works)',
    'Stored XSS (unescaped output)',
    'Insecure cookie flags'
  ];

  for (const app of APPS) {
    console.log(`--- ${app.name} (${app.base}) ---`);
    results[app.name] = await runChecksForApp(app);
    for (const name of CHECK_NAMES) {
      const outcome = results[app.name][name];
      console.log(`  [${verdict(outcome.vulnerable)}] ${name}`);
      console.log(`      ${outcome.evidence}`);
    }
    console.log('');
  }

  // Summary table
  console.log('===== SUMMARY =====\n');
  const col1 = 'Check';
  const col2 = APPS[0].name;
  const col3 = APPS[1].name;
  console.log(`${col1.padEnd(42)} | ${col2.padEnd(16)} | ${col3}`);
  console.log('-'.repeat(42) + '-+-' + '-'.repeat(16) + '-+-' + '-'.repeat(16));
  for (const name of CHECK_NAMES) {
    const v1 = verdict(results[APPS[0].name][name].vulnerable);
    const v2 = verdict(results[APPS[1].name][name].vulnerable);
    console.log(`${name.padEnd(42)} | ${v1.padEnd(16)} | ${v2}`);
  }
  console.log('');
})();

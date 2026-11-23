# Vulnerable Session Management Demo (Phase 1)

Part of the "Session Management Security Demonstration" project.
This is the **intentionally insecure** version of the app, built to
demonstrate real session management vulnerabilities in a controlled,
local environment. The hardened version in `../hardened-app/` fixes
every issue found here — see `../docs/` for the full write-up.

⚠️ **Run this only on localhost.** Never deploy this code anywhere
public — it is deliberately broken.

## Setup

```bash
npm install
node server.js
```

Then visit `http://localhost:3000`.

## What's vulnerable, and where in the code

| # | Vulnerability | Location |
|---|---|---|
| 1 | Predictable, sequential session IDs | `server.js` — `weakGenId()` |
| 2 | Hardcoded session secret | `server.js` — `secret: 'super-secret-key'` |
| 3 | Insecure cookie flags (`httpOnly: false`, `secure: false`) | `server.js` — `session({ cookie: {...} })` |
| 4 | No session regeneration on login (session fixation) | `server.js` — `/login` route |
| 5 | No session expiration / idle timeout | `server.js` — session config (no `maxAge`) |
| 6 | Broken logout (clears cookie but not server-side session) | `server.js` — `/logout` route |
| 7 | Stored XSS via unescaped comment board | `views/dashboard.ejs` — `<%- m.text %>` |

## Demos

### 1. Predictable session ID + leaked secret → session hijack
```bash
node attacks/guess_session.js
```
This signs guessed session IDs (`sess_1000`–`sess_1050`) using the
same hardcoded secret the server uses, and finds any live logged-in
session — no password required. Sign up/log in as a test user first
so there's an active session to find.

### 2. Session fixation
1. Note a session ID from a fresh request (e.g. via `/whoami`).
2. Send that exact `connect.sid` cookie back on a `/login` POST.
3. Call `/whoami` again with the same cookie — it's now authenticated,
   and the session ID never changed. Anyone who had that cookie value
   beforehand (e.g. via a crafted link, if the app also accepted the
   ID from a URL parameter) would now be logged in as the victim too.

### 3. Cookie theft via XSS
1. Log in, go to the dashboard.
2. Post a comment containing `<script>alert(document.cookie)</script>`.
3. It executes and can read `document.cookie` directly — because
   `httpOnly` is disabled, a real attacker payload could exfiltrate
   the session cookie to a remote server instead of just alerting it.

### 4. Broken logout
1. Log in, copy the `connect.sid` cookie value (or save the cookie jar).
2. Click "Logout".
3. Reuse the saved cookie against `/dashboard` or `/whoami` — it's
   often still accepted, because the server never destroyed the
   session record, only cleared the browser's copy.

## `/whoami` debug endpoint

Added purely for this demo — shows the raw session ID and session
object so vulnerabilities are easy to observe without devtools.
**A real app should never expose this.**

## Next phases

See `../hardened-app/` for the fixed version and `../docs/` for the
full vulnerability report and before/after verification evidence.

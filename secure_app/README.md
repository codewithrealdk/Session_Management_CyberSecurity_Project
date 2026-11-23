# Hardened Session Management Demo (Phase 3)

The secure counterpart to `vulnerable-app/`. Same features (signup,
login, dashboard, comment board, logout) — session handling rebuilt
to fix every finding from the Phase 2 report.

## Setup

```bash
npm install
node server.js
```

Visit `http://localhost:3001` (different port so both apps can run
at the same time for side-by-side comparison).

## Fixes, mapped to Phase 2 findings

| Finding | Fix | Where |
|---|---|---|
| #1 Predictable IDs + hardcoded secret | `crypto.randomBytes(32)` session IDs (256-bit); secret from `SESSION_SECRET` env var (random fallback at startup, never hardcoded) | `server.js` — `strongGenId`, `SESSION_SECRET` |
| #2 Session fixation | `req.session.regenerate()` on every successful login — issues a brand new ID, kills any pre-existing one | `server.js` — `/login` |
| #3 Broken logout | `req.session.destroy()` removes the session server-side (not just the cookie) | `server.js` — `/logout` |
| #4 Stored XSS | Comment text rendered with escaped EJS output (`<%= %>`) instead of raw (`<%- %>`) | `views/dashboard.ejs` |
| #5 Insecure cookie flags | `httpOnly: true`, `sameSite: 'strict'`, `secure: true` in production, `maxAge` + `rolling: true` for a 15-minute idle timeout | `server.js` — `cookie: {...}` |

Also switched from the default in-memory session store to a
persistent file-based store (`session-file-store`) so expiration is
actually enforced server-side and sessions survive a server restart.

**Note on a race condition found during testing:** `/login` originally
called `req.session.save()` manually *in addition to* letting
express-session's automatic save-on-response run — producing two
concurrent writes to the same session file. Under rapid back-to-back
requests, the slower of the two writes could land after a later
`/logout`'s delete, silently resurrecting a destroyed session. Fixed
by removing the redundant manual `save()` call. See
`../docs/phase4-automated-test-log.md` for the full writeup.

## Verifying the fixes

`attacks/guess_session.js` replays the Phase 2 session-guessing
attack against this app (port 3001) and confirms it fails — forged
cookies signed with the old leaked secret are rejected, and there's
no sequential ID space to brute-force.

To verify the other three fixes manually, repeat the Phase 2 demo
steps (see `vulnerable-app/README.md`) against `localhost:3001`
instead of `:3000` — each one now fails:
- Logging in after pre-setting a session cookie issues a **new** ID (no fixation)
- Reusing a cookie after logout gets a fresh, unauthenticated session (no bypass)
- Posting `<script>...</script>` in a comment renders as plain text, not executable code

## Note on `secure: true`

The cookie's `secure` flag is conditional on `NODE_ENV === 'production'`
here, because this demo runs over plain HTTP on localhost (browsers
refuse `Secure` cookies over non-HTTPS origins, which would break the
demo). In any real deployment, this must always be `true` and the app
must be served over HTTPS.

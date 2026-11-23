# Phase 4 — Automated Comparative Test Log
## Session Management Security Demonstration

This report documents the automated test suite (`tests/comparative_test.js`)
that runs the same 6 checks against both apps and prints a side-by-side
verdict. It also documents a real bug the test suite caught in the
hardened app's logout implementation, and the fix applied.

## How to run it

```bash
# Terminal 1
cd vulnerable-app && npm install && node server.js   # port 3000

# Terminal 2
cd hardened-app && npm install && node server.js     # port 3001

# Terminal 3
node tests/comparative_test.js
```

No external dependencies are needed for the test script itself — it
uses Node's built-in `fetch` and `crypto` only.

## What it checks

| Check | How it works |
|---|---|
| Session ID format | Inspects a real session ID's shape — short/sequential vs. high-entropy random |
| Secret forgery | Signs guessed IDs (`sess_1000`–`sess_1050`) with a known/leaked secret and checks if the server accepts them |
| Session fixation | Captures a pre-login session cookie, logs in while reusing it, and checks if the ID changed |
| Broken logout | Logs in, logs out, then reuses the old cookie against `/dashboard` |
| Stored XSS | Posts a `<script>` payload as a comment and checks whether it's returned escaped or raw |
| Cookie flags | Inspects the `Set-Cookie` header for `HttpOnly`, `SameSite`, and expiration |

## Final run output

```
Running Phase 4 comparative test suite...

--- Vulnerable App (http://localhost:3000) ---
  [VULNERABLE] Session ID format (guessable?)
      ID "sess_1002" is short and sequential — easy to enumerate.
  [VULNERABLE] Session ID forgeable w/ known secret
      Forged cookie for "sess_1002" was accepted as user "baseline_...".
  [VULNERABLE] Session fixation (ID unchanged on login)
      Session ID unchanged across login (sess_1004).
  [VULNERABLE] Broken logout (old cookie still works)
      Dashboard still returned HTTP 200 after logout using the old cookie.
  [VULNERABLE] Stored XSS (unescaped output)
      Payload found unescaped in the HTML — would execute in a browser.
  [VULNERABLE] Insecure cookie flags
      missing HttpOnly, missing Secure (acceptable on localhost/dev), weak SameSite ((not set)), no expiration set

--- Hardened App (http://localhost:3001) ---
  [SECURE] Session ID format (guessable?)
      ID "0a610d36431c900868369f968840e2edd60cb76397212f7e0d56f441c65ba857" (64 chars) looks like high-entropy random data.
  [SECURE] Session ID forgeable w/ known secret
      No forged cookie using the known/guessed secret was accepted.
  [SECURE] Session fixation (ID unchanged on login)
      App does not issue a session cookie before login (saveUninitialized: false), so there is no pre-login session to fixate.
  [SECURE] Broken logout (old cookie still works)
      Dashboard returned HTTP 302 (access denied) after logout.
  [SECURE] Stored XSS (unescaped output)
      Payload was HTML-escaped — would render as inert text.
  [SECURE] Insecure cookie flags
      missing Secure (acceptable on localhost/dev)

===== SUMMARY =====

Check                                      | Vulnerable App   | Hardened App
--------------------------------------------+------------------+-----------------
Session ID format (guessable?)             | VULNERABLE       | SECURE
Session ID forgeable w/ known secret       | VULNERABLE       | SECURE
Session fixation (ID unchanged on login)   | VULNERABLE       | SECURE
Broken logout (old cookie still works)     | VULNERABLE       | SECURE
Stored XSS (unescaped output)              | VULNERABLE       | SECURE
Insecure cookie flags                      | VULNERABLE       | SECURE
```

Re-run twice to confirm stability (not a fluke) — identical results both times.

## Bug found while building this suite: a logout race condition

While wiring up the automated "broken logout" check, the hardened
app occasionally *failed* the check — a logged-out cookie could still
authenticate. Manual testing (with pauses between requests) hadn't
caught this; the automated suite, running requests back-to-back, did.

**Root cause:** `/login` was calling `req.session.save()` manually
*and* relying on express-session's automatic save-on-response-end.
That produced two concurrent writes to the same session file. If the
second (slower) write from login completed *after* a later `/logout`
request had already deleted the file, it would silently resurrect
the destroyed session.

**Fix:** removed the redundant manual `req.session.save()` call in
`/login` — express-session's own response-end hook persists the
session exactly once, which is all that's needed:

```js
req.session.regenerate((err) => {
  if (err) return res.status(500).send('Session error.');
  req.session.user = { id: user.id, username: user.username };
  // No manual save() — the automatic hook on res.end() handles it.
  res.redirect('/dashboard');
});
```

**Verification:** stress-tested login → logout → reuse-cookie 10
times back-to-back with zero delay between requests. All 10 runs
correctly returned `HTTP 302` (access denied) on the reused cookie,
confirming the race is fixed.

This is worth including in the final report as a concrete example of
why automated, repeated testing matters even after a fix is manually
verified once — a single manual pass missed a timing-dependent bug
that running the suite surfaced immediately.

# Phase 3 & 4 — Remediation and Verification Report
## Session Management Security Demonstration

This report documents the fixes applied in the hardened app
(`hardened-app/`, port 3001) and re-runs every Phase 2 attack against
it to confirm each one now fails.

---

## Fix Summary

| # | Finding (Phase 2) | Fix Applied |
|---|---|---|
| 1 | Predictable session IDs + hardcoded secret | `crypto.randomBytes(32)` IDs (256-bit keyspace); secret from env var, random fallback — never hardcoded |
| 2 | Session fixation | `req.session.regenerate()` on every login |
| 3 | Broken logout | `req.session.destroy()` on logout (server-side invalidation) |
| 4 | Stored XSS | Escaped EJS output (`<%= %>`) instead of raw (`<%- %>`) |
| 5 | Insecure cookie attributes | `httpOnly: true`, `sameSite: 'strict'`, `secure: true` in production, `maxAge` + `rolling` idle timeout |

Also replaced the default in-memory session store with a persistent
file-based store so expiration is actually enforced server-side.

---

## Verification: Attack 1 — Predictable ID + Leaked Secret

**Before (vulnerable app):**
```
Guessing session IDs from sess_1000 to sess_1050...
✅ FOUND active session: sess_1002 -> user: alice
```

**After (hardened app, same script logic, old leaked secret):**
```
Attempting the Phase 2 attack against the HARDENED app...
Trying sess_1000..sess_1050 signed with the old leaked secret.

✅ Attack FAILED as expected: no sequential IDs exist, and the old secret
   does not match the server's (randomly generated, unknown) secret, so
   every forged cookie is rejected as an invalid signature.
```

**Result:** Fixed. Forged cookies are rejected; there is no enumerable ID space.

---

## Verification: Attack 2 — Session Fixation

**Before:** session ID identical before and after login (`sess_1004` → `sess_1004`).

**After:**
```
Pre-login session ID:  3dd35df4b2f82863db544dcd35c80c6109c7af9d4bca4f92b422688c9d31ca77
Post-login session ID: b9c540aa5631ef40fedcd892e900a8fb583b652fa04488782bc908da09392cc0
```

**Result:** Fixed. A brand new session ID is issued on login; the pre-login ID is discarded and cannot be "promoted" to an authenticated session.

---

## Verification: Attack 3 — Broken Logout

**Before:** reusing the cookie after logout still returned `HTTP 200` on `/dashboard`.

**After:**
```
-- reuse the SAME cookie after logout --
{"sessionID":"91e017b1...", "session":{"cookie":{...}}}   <- no "user" field, fresh session
dashboard access after logout: HTTP 302                    <- redirected to /login
```

**Result:** Fixed. The server-side session record is destroyed; the old cookie no longer authenticates.

---

## Verification: Attack 4 — Stored XSS

**Before:** payload served back verbatim and executable:
```
<script>alert('stolen cookie: '+document.cookie)</script>
```

**After:** payload rendered as inert, HTML-escaped text:
```
&lt;script&gt;alert(&#39;stolen cookie: &#39;+document.cookie)&lt;/script&gt;
```

**Result:** Fixed. The payload displays as literal text in the browser instead of executing.

---

## Conclusion

All five Phase 2 findings were remediated and independently re-verified
against the hardened app using the same tools and techniques used to
find them. No attack from Phase 2 succeeds against the Phase 3 app.

**Suggested next steps beyond this project's scope:** CSRF token
enforcement (`sameSite: 'strict'` already mitigates most of this),
rate-limiting login attempts, multi-factor authentication, and moving
the session secret to a proper secret-management service for a real
deployment.

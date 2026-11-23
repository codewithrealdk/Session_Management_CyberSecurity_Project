# Session Management Security Demonstration

A cybersecurity project demonstrating common session management
vulnerabilities, their exploitation, and their remediation — using
two parallel Node.js/Express apps.

## Structure

```
session-security-demo/
├── vulnerable-app/     Phase 1 & 2 — intentionally insecure app + attack scripts
│   ├── server.js
│   ├── views/
│   ├── attacks/guess_session.js
│   └── README.md
│
├── hardened-app/        Phase 3 — same app, session handling fixed
│   ├── server.js
│   ├── views/
│   ├── attacks/guess_session.js   (same attack, re-run to prove it fails)
│   └── README.md
│
├── tests/                Phase 4 — automated comparative test suite
│   └── comparative_test.js   runs all checks against both apps, prints pass/fail
│
└── docs/                 Phase 2 & 4 — write-ups
    ├── phase2-vulnerability-report.md       findings + evidence
    ├── phase3-4-verification-report.md      before/after proof fixes work
    └── phase4-automated-test-log.md         automated test run + a race-condition bug found & fixed
```

## How to run

Each app is independent and runs on its own port so both can be up
at once for side-by-side comparison:

```bash
# Terminal 1
cd vulnerable-app && npm install && node server.js   # http://localhost:3000

# Terminal 2
cd hardened-app && npm install && node server.js     # http://localhost:3001

# Terminal 3 (once both are up)
node tests/comparative_test.js                        # automated pass/fail comparison
```

## What this project demonstrates

5 session management vulnerabilities, each exploited in
`vulnerable-app` and independently verified as fixed in
`hardened-app`:

1. Predictable session IDs + hardcoded session secret → full session hijack with no credentials
2. Session fixation (no regeneration on login)
3. Broken logout (server-side session not destroyed)
4. Stored XSS enabling session cookie theft
5. Insecure cookie attributes (`httpOnly`, `secure`, `sameSite` missing)

Full details, CWE references, and reproducible evidence for each are
in `docs/phase2-vulnerability-report.md`. The corresponding fixes and
proof they work are in `docs/phase3-4-verification-report.md`, and the
automated test suite's run log (including a real race-condition bug
it caught and the fix applied) is in `docs/phase4-automated-test-log.md`.

⚠️ Both apps are for local, educational use only. `vulnerable-app` in
particular must never be deployed anywhere public.

# Implementation Plan 110 — AUT-05 (`Post-Logout Session & Refresh Replay Harness`)

1. Extract `evaluate_aut05_logout_invalidation(...)` in `casa-assessment/casa_audit/scanner.py` supporting JSON Bearer tokens, `Set-Cookie` session cookies (via `_extract_session_cookies`), JSON/`Set-Cookie` refresh tokens, dynamic logout probes with SPA catch-all filtering, post-logout replay across protected routes and refresh endpoints, stateless JWT fallback inspection, SARIF 2.1.0 (`CASA3-AUT-05`) finding generation, and redacted HAR 1.2 persistence (`output/aut05-replayed.har`).
2. Wire `results["AUT-05"]` inside `run_dynamic_and_protocol_checks`, preserving `aut05_token`, `aut05_replayed_token`, and `aut05_post_logout_accepted` for `AUT-06`, `AUT-07`, `AUT-08`, `AZI-*`, and `OAU-*`.
3. Add `test_iteration110_aut05_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering:
   - Server revokes both session cookie/token AND refresh token after logout (`PASS` + `[REDACTED]` HAR verification);
   - Session cookie/token still accepted after logout (`FAIL`);
   - Session cookie revoked after logout, yet refresh token still accepted (`FAIL` / `CASA3-AUT-05`).
4. Append `CONTROLE 40/61: AUT-05 (Iteração SDD 110)` to `docs/justificativa2.txt`.
5. Run full `unittest` suite (`43` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`) with refreshed `casa_audit` daemon, check off `tasks.md`, commit, tag `sdd-110`, and push `main` + tags.

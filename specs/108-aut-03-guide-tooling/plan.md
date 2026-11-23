# Implementation Plan 108 — AUT-03 (`Session Fixation & Post-Auth Replay Harness`)

1. Extract `_extract_session_cookies(raw_set_cookie)` and `evaluate_aut03_session_fixation(...)` in `casa-assessment/casa_audit/scanner.py` implementing pre-auth `Set-Cookie` capture (comma-safe against `Expires=...` dates), fixation injection at login, token/cookie rotation comparison across JSON bodies and `Set-Cookie` headers, post-login replay against protected routes, SARIF 2.1.0 (`CASA3-AUT-03`) finding emission, and dedicated redacted HAR 1.2 persistence (`output/aut03-replayed.har`).
2. Wire `results["AUT-03"]` inside `run_dynamic_and_protocol_checks`, preserving `post_token3` compatibility for `AUT-04`, `AUT-05`, and `AUT-08`.
3. Add `test_iteration108_aut03_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering:
   - **PASS:** Server rotates pre-auth session cookie on login and rejects replayed pre-auth cookie on protected routes (`401`) with redacted HAR `[REDACTED]` verification.
   - **FAIL (Unchanged Identifier / Fixation):** Server preserves/adopts pre-auth cookie across authentication -> `FAIL` (`CASA3-AUT-03`).
   - **FAIL (Pre-Auth Identifier Remains Valid After Login):** Server issues a new token on login yet fails to invalidate the pre-auth session ID so replay still returns `200` on protected route -> `FAIL` (`CASA3-AUT-03`).
4. Append `CONTROLE 38/61: AUT-03 (Iteração SDD 108)` to `docs/justificativa2.txt`.
5. Run full `unittest` suite (`41` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`) with refreshed `casa_audit` daemon, check off `tasks.md`, commit, tag `sdd-108`, and push `main` + tags.

# Implementation Plan 114 — AZI-01 (`3-Mode Anti-CSRF Replay & Re-Read Harness`)

1. Extract `_extract_csrf_token(...)` and `evaluate_azi01_anti_csrf(...)` in `casa-assessment/casa_audit/scanner.py` supporting hidden form fields, meta tags, `X-CSRF-Token` headers, `XSRF-TOKEN` cookies across two distinct authenticated sessions (Session A & Session B), 3-mode cross-origin CSRF replay + re-read state verification, `SameSite=None` cookie detection, SARIF 2.1.0 (`CASA3-AZI-01`) finding emission, and dedicated redacted HAR 1.2 persistence (`output/azi01-replayed.har`).
2. Wire `results["AZI-01"]` inside `run_dynamic_and_protocol_checks`, preserving `session_a_tok` for `AZI-02` and `AZI-05`.
3. Add `test_iteration114_azi01_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering:
   - **PASS:** Server enforces session-bound CSRF token rejecting removed, replaced, and Session B CSRF token replays with `403`, zero state change on re-read, and no `SameSite=None` cookies (`[REDACTED]` HAR verified);
   - **FAIL (CSRF Removed/Unprotected):** Server accepts cross-origin Cookie POST without CSRF token and mutates state on re-read -> `FAIL`;
   - **FAIL (Global/Non-Session-Bound CSRF Token + `SameSite=None`):** Server validates CSRF format yet accepts Session B's CSRF token on Session A (`csrf_token_second_session`) -> `FAIL` (`CASA3-AZI-01`).
4. Append `CONTROLE 44/61: AZI-01 (Iteração SDD 114)` to `docs/justificativa2.txt`.
5. Run full `unittest` suite (`47` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`) with refreshed `casa_audit` daemon, check off `tasks.md`, commit, tag `sdd-114`, and push `main` + tags.

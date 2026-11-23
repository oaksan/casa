# Implementation Plan 111 — AUT-06 (`OWASP ZAP 10010/10011/10054` + `Set-Cookie Inspector`)

1. Enable ZAP passive rules `10010`, `10011`, and `10054` at `Low` threshold in `run_zap_automation`, and preserve multi-header `Set-Cookie` lists (`resp.headers.get_all("Set-Cookie")`) inside `http_probe` in `casa-assessment/casa_audit/scanner.py`.
2. Extract `evaluate_aut06_session_cookie_flags(...)` in `casa-assessment/casa_audit/scanner.py` combining OWASP ZAP (`10010`/`10011`/`10054`), multi-header `Set-Cookie` attribute parsing (`Secure`, `HttpOnly`, `SameSite=Lax|Strict`), behavioral session-cookie identification (cookie-removal probe), client-side JS session cookie detection (`cookieService.put('token', ...)`), SARIF 2.1.0 (`CASA3-AUT-06`) emission, and dedicated redacted HAR 1.2 persistence (`output/aut06-replayed.har`).
3. Wire `results["AUT-06"]` inside `run_dynamic_and_protocol_checks`, reusing `zap_domain4_report` so full scans add zero extra ZAP invocations.
4. Add `test_iteration111_aut06_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering:
   - Server setting `Secure; HttpOnly; SameSite=Strict` on login `Set-Cookie` (plus benign preference cookie ignored) with real ZAP run (`PASS` + `[REDACTED]` HAR verified);
   - Session cookie missing `HttpOnly` / `SameSite=Strict` (`FAIL` flagged by both parser and real OWASP ZAP rule `10010`/`10054`);
   - Cookie-less JSON login relying on client-side cookie or missing server `Set-Cookie` (`FAIL` / `CASA3-AUT-06`).
5. Append `CONTROLE 41/61: AUT-06 (Iteração SDD 111)` to `docs/justificativa2.txt`.
6. Run full `unittest` suite (`44` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`) with refreshed `casa_audit` daemon, check off `tasks.md`, commit, tag `sdd-111`, and push `main` + tags.

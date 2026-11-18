# Implementation Plan — Iteration 049 (`AUT-06`)

1. Replace the 3-line `AUT-06` header check in `casa-assessment/casa_audit/scanner.py` with `split_set_cookie_headers` + `inspect_cookie_flags` auditing all `crawled_exchanges` (`160` HTTP responses) strictly for `Secure`, `HttpOnly`, and `SameSite=Lax|Strict`.
2. Add active session-cookie backend validation (`/rest/user/whoami` with `Cookie: token=...`) and client-side `cookieService.put('token', ...)` detection.
3. Emit `CASA3-AUT-06` results into `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-049`, and push.

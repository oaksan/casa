# Tasks — Iteration 049 (`AUT-06`)

- [x] Implement crawl-wide `Set-Cookie` parser (`Secure`, `HttpOnly`, `SameSite=Lax|Strict`) and client-side cookie audit in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — inspected 160 HTTP responses, confirmed client-side `'token'` cookie write lacking `HttpOnly`/`Secure`/`SameSite` (`CASA3-AUT-06` in `output/dast-findings.sarif`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 41/61: AUT-06`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-049`, and push `main` + `--tags` to `origin`.

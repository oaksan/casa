# Tasks — Iteration 037 (`CFG-05`)

- [x] Implement multi-route HTML clickjacking protection audit (`X-Frame-Options` DENY/SAMEORIGIN & strict `frame-ancestors` parser) in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — `PASS` confirmed across 39/39 HTML routes (`X-Frame-Options=['SAMEORIGIN']`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 29/61: CFG-05`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-037`, and push `main` + `--tags` to `origin`.

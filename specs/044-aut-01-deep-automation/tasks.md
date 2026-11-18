# Tasks — Iteration 044 (`AUT-01`)

- [x] Add sensitive header redaction to `output/dast-capture.har` and implement 12-pair default/vendor credential replay harness in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 5/12 credential pairs authenticated (`admin@juice-sh.op`, `jim@juice-sh.op`, `bender@juice-sh.op`, `mc.safesearch@juice-sh.op`, `demo`/`demo`); 72 HAR auth headers redacted.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 36/61: AUT-01`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-044`, and push `main` + `--tags` to `origin`.

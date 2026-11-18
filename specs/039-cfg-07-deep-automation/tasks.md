# Tasks — Iteration 039 (`CFG-07`)

- [x] Implement authenticated session login + 9-route strict `Cache-Control: no-store` audit in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 9/9 authenticated/sensitive routes missing `no-store` recorded in `output/dast-findings.sarif`.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 31/61: CFG-07`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-039`, and push `main` + `--tags` to `origin`.

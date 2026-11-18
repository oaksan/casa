# Tasks — Iteration 054 (`AZI-03`)

- [x] Implement 8-probe differential SQLi & NoSQL `$where`/operator injection scanner in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — confirmed 4 real SQLi/NoSQLi findings (`CASA3-AZI-03` x4 in `output/dast-findings.sarif`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 46/61: AZI-03`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-054`, and push `main` + `--tags` to `origin`.

# Tasks — Iteration 045 (`AUT-02`)

- [x] Implement 200-sample fresh-authentication collector + NIST SP 800-90B MCV min-entropy estimator in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — corrected false PASS to true FAIL (`8/200` unique, `192` duplicates, max collision `34/200`, min-entropy `2.56 bits` < `64.0`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 37/61: AUT-02`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-045`, and push `main` + `--tags` to `origin`.

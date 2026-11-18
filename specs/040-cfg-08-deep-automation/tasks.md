# Tasks — Iteration 040 (`CFG-08`)

- [x] Implement 21-probe multi-origin CORS allowlist & reflection audit in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 5 `CASA3-CFG-08` violations flagged across sensitive/authenticated endpoints and `OPTIONS` preflight.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 32/61: CFG-08`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-040`, and push `main` + `--tags` to `origin`.

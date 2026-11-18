# Tasks — Iteration 048 (`AUT-05`)

- [x] Implement active logout probing (6 probes with SPA filter) and post-logout session/refresh replay harness in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 3/3 protected routes returned `HTTP 200` on post-logout replay (`CASA3-AUT-05` in `output/dast-findings.sarif`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 40/61: AUT-05`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-048`, and push `main` + `--tags` to `origin`.

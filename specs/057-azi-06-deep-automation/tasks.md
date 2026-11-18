# Tasks — Iteration 057 (`AZI-06`)

- [x] Implement active `NoRedirect` open-redirect & HPP authorization differential analyzer in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 2 real CWE-601/CWE-235 bypasses confirmed across 10 probes (`CASA3-AZI-06` x2 in `output/dast-findings.sarif`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 49/61: AZI-06`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-057`, and push `main` + `--tags` to `origin`.

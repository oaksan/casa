# Tasks — Iteration 056 (`AZI-05`)

- [x] Implement 9-probe traversal matrix (encoded, double-encoded, null-byte, absolute, UNC) and live RFI callback probe (`POST /profile/image/url`) in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 3 real CWE-22/CWE-98 violations confirmed (`CASA3-AZI-05` x3 in `output/dast-findings.sarif`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 48/61: AZI-05`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-056`, and push `main` + `--tags` to `origin`.

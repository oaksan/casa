# Tasks — Iteration 052 (`AZI-01`)

- [x] Implement 3-mode cross-origin CSRF replay harness (removed, replaced, cross-session) + re-read state verification + `SameSite=None` audit in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — all 3 CSRF replay modes succeeded (`HTTP 200`) with state mutations verified on re-read (`CASA3-AZI-01` x3 in `output/dast-findings.sarif`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 44/61: AZI-01`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-052`, and push `main` + `--tags` to `origin`.

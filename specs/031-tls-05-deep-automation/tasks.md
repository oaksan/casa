# Tasks: SDD Iteration 31 — Control TLS-05 Deep Automation & Justification

- [x] T001 Implement multi-endpoint HSTS audit (`HSTS_time >= 31536000` + RFC 6797 §7.2) in `casa-assessment/casa_audit/scanner.py`
- [x] T002 Persist `HSTS_time` and `tls05Hsts` into `casa-assessment/output/tls-scan.json`
- [x] T003 Append section `CONTROLE 23/61: TLS-05 (Iteração SDD 031)` to `docs/justificativa.txt`
- [x] T004 Update `casa-assessment/tests/test_iteration1.py`, run tests, commit, tag `sdd-031`, and push to GitHub

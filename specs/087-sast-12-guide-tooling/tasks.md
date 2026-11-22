# Tasks: SDD 087 — SAST-12 Guide Tooling (`semgrep` + `trivy` + `docker`)

- [x] Create SDD 087 spec, plan, and tasks
- [x] Expand `CASA3-SAST-12-*` Semgrep rules in `casa-assessment/rules/casa3_al1_sast.yml` and validate via `semgrep --validate`
- [x] Add `run_trivy_sast12` + upgraded `evaluate_sast12_secrets_management_and_iac` and `SAST-12` evidence/label in `casa-assessment/casa_audit/scanner.py`
- [x] Add `test_iteration87_sast12_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Run live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 087 (`SAST-12`) in `docs/justificativa2.txt`, commit, tag `sdd-087`, and push to GitHub

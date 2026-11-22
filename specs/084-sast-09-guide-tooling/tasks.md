# Tasks: SDD 084 — SAST-09 Guide Tooling (`semgrep` CWE-502)

- [x] Create SDD 084 spec, plan, and tasks
- [x] Expand `CASA3-SAST-09-*` multi-language rules in `casa-assessment/rules/casa3_al1_sast.yml` and validate via `semgrep --validate`
- [x] Add `evaluate_sast09_deserialization` and `SAST-09` error-gating/metadata in `casa-assessment/casa_audit/scanner.py`
- [x] Add `test_iteration84_sast09_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Run live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 084 (`SAST-09`) in `docs/justificativa2.txt`, commit, tag `sdd-084`, and push to GitHub

# Tasks: SDD 085 — SAST-10 Guide Tooling (`semgrep` CWE-95 Taint)

- [x] Create SDD 085 spec, plan, and tasks
- [x] Expand `CASA3-SAST-10-*` multi-language `mode: taint` rules in `casa-assessment/rules/casa3_al1_sast.yml` and validate via `semgrep --validate`
- [x] Add `evaluate_sast10_dynamic_execution` and `SAST-10` error-gating/metadata in `casa-assessment/casa_audit/scanner.py`
- [x] Add `test_iteration85_sast10_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Run live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 085 (`SAST-10`) in `docs/justificativa2.txt`, commit, tag `sdd-085`, and push to GitHub

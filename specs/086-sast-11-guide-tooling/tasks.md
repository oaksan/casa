# Tasks: SDD 086 — SAST-11 Guide Tooling (`semgrep` CWE-22 Taint)

- [x] Create SDD 086 spec, plan, and tasks
- [x] Expand `CASA3-SAST-11-*` multi-language `mode: taint` rules in `casa-assessment/rules/casa3_al1_sast.yml` and validate via `semgrep --validate`
- [x] Add `evaluate_sast11_path_traversal` and `SAST-11` error-gating/metadata in `casa-assessment/casa_audit/scanner.py`
- [x] Add `test_iteration86_sast11_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Run live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 086 (`SAST-11`) in `docs/justificativa2.txt`, commit, tag `sdd-086`, and push to GitHub

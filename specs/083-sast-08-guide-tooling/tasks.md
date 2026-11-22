# Tasks: SDD 083 — SAST-08 Guide Tooling (`semgrep` SQL/NoSQL Taint)

- [x] Create SDD 083 spec, plan, and tasks
- [x] Convert `CASA3-SAST-08-*` rules in `casa-assessment/rules/casa3_al1_sast.yml` to multi-language `mode: taint` and validate via `semgrep --validate`
- [x] Add `evaluate_sast08_sql_injection` and `SAST-08` error-gating/metadata in `casa-assessment/casa_audit/scanner.py`
- [x] Add `test_iteration83_sast08_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Run live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 083 (`SAST-08`) in `docs/justificativa2.txt`, commit, tag `sdd-083`, and push to GitHub

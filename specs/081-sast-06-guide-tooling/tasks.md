# Tasks: SDD 081 — SAST-06 Guide Tooling (`semgrep` CSPRNG Taint)

- [x] Create SDD 081 spec, plan, and tasks
- [x] Expand `CASA3-SAST-06-*` multi-language `mode: taint` rules in `casa-assessment/rules/casa3_al1_sast.yml` and validate via `semgrep --validate`
- [x] Add `evaluate_sast06_csprng_randomness` and `ERROR`-level gating + tool metadata in `casa-assessment/casa_audit/scanner.py`
- [x] Add `test_iteration81_sast06_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Test live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 081 (`SAST-06`) in `docs/justificativa2.txt`, commit, tag `sdd-081`, and push to GitHub

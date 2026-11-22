# Tasks: SDD 088 — SAST-13 Guide Tooling (`semgrep` + `scripted replay harness`)

- [x] Create SDD 088 spec, plan, and tasks
- [x] Expand `CASA3-SAST-13-*` rules in `casa-assessment/rules/casa3_al1_sast.yml` and validate via `semgrep --validate`
- [x] Upgrade `SAST-13` evaluator & auth/token-refresh/payment canary replay harness in `casa-assessment/casa_audit/scanner.py`
- [x] Add `test_iteration88_sast13_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Run live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 088 (`SAST-13`) in `docs/justificativa2.txt`, commit, tag `sdd-088`, and push to GitHub

# Tasks: SDD 082 — SAST-07 Guide Tooling (`semgrep` + `ZAP` / Lab-Account Probe)

- [x] Create SDD 082 spec, plan, and tasks
- [x] Expand multi-language `CASA3-SAST-07-*` rules in `casa-assessment/rules/casa3_al1_sast.yml` and validate via `semgrep --validate`
- [x] Upgrade `SAST-07` static/active/ZAP hybrid verification in `casa-assessment/casa_audit/scanner.py`
- [x] Add `test_iteration82_sast07_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Test live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 082 (`SAST-07`) in `docs/justificativa2.txt`, commit, tag `sdd-082`, and push to GitHub

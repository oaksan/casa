# Tasks: SDD 079 — SAST-04 Guide Tooling (`semgrep` `mode: taint`)

- [x] Create SDD 079 spec, plan, and tasks
- [x] Upgrade `CASA3-SAST-04-*` rules in `casa-assessment/rules/casa3_al1_sast.yml` to `mode: taint` + `INFO` ETag/cache rules and run `semgrep --validate`
- [x] Factor shared Semgrep error-level SARIF evaluator and add `evaluate_sast04_weak_hashes` + `ERROR` gating in `run_sast_checks`
- [x] Add `test_iteration79_sast04_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Test live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 079 (`SAST-04`) in `docs/justificativa2.txt`, commit, tag `sdd-079`, and push to GitHub

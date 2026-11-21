# Tasks: SDD 078 — SAST-03 Guide Tooling (`semgrep`)

- [x] Create SDD 078 spec, plan, and tasks
- [x] Expand multi-language `CASA3-SAST-03-*` AST rules in `casa-assessment/rules/casa3_al1_sast.yml` and validate via `semgrep --validate`
- [x] Optimize `run_sast_checks` to single-pass `--json --sarif-output` and add `evaluate_sast03_banned_ciphers` enforcing `error`-level filtering
- [x] Add `test_iteration78_sast03_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Test live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 078 (`SAST-03`) in `docs/justificativa2.txt`, commit, tag `sdd-078`, and push to GitHub

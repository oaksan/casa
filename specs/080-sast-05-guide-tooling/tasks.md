# Tasks: SDD 080 — SAST-05 Guide Tooling (`semgrep`)

- [x] Create SDD 080 spec, plan, and tasks
- [x] Expand `CASA3-SAST-05-*` Semgrep AST rules (`TS/JS` + `Python`) with `metavariable-comparison` and validate via `semgrep --validate`
- [x] Upgrade `evaluate_sast05_password_kdf` for KDF parameter provenance, Argon2id/SHA-256 checks, and CSPRNG salt verification
- [x] Add `test_iteration80_sast05_guide_tooling` in `casa-assessment/tests/test_iteration1.py` and run full unittest suite
- [x] Test live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`)
- [x] Record SDD 080 (`SAST-05`) in `docs/justificativa2.txt`, commit, tag `sdd-080`, and push to GitHub

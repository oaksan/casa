# Tasks — Iteration 058 (`OAU-01`)

- [x] Implement live JS bundle + OAuth source `response_type != code` & ROPC `grant_type=password` analyzer in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 5 `CASA3-OAU-01` Implicit Flow findings detected across `main.js`, `login.component.ts`, `oauth.component.ts`, and `user.service.ts`.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 50/61: OAU-01`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-058`, and push `main` + `--tags` to `origin`.

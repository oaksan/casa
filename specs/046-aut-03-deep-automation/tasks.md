# Tasks — Iteration 046 (`AUT-03`)

- [x] Implement pre-auth session capture, fixation cookie injection, rotation validation, and post-login pre-ID replay harness in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — `PASS` confirmed (0 pre-auth cookies, distinct 761-char JWT issued, 2/2 pre-auth replays rejected).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 38/61: AUT-03`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-046`, and push `main` + `--tags` to `origin`.

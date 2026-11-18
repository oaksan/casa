# Tasks — Iteration 042 (`CFG-10`)

- [x] Implement differential auth/unauth replay, admin wordlist probing, normalized LCS similarity (`>= 0.90`), and SPA fallback filtering in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 6 unauthenticated admin/operational endpoints confirmed (`LCS` 0.926–1.000).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 34/61: CFG-10`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-042`, and push `main` + `--tags` to `origin`.

# Tasks — Iteration 043 (`CFG-11`)

- [x] Replace hardcoded stub with real `dig` CNAME chain traversal, `socket.getaddrinfo`, and 16-provider takeover fingerprint verification in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — `localhost` resolved cleanly (`['127.0.0.1', '::1']`), 0 takeover fingerprints matched -> `PASS`.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 35/61: CFG-11`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-043`, and push `main` + `--tags` to `origin`.

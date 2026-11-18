# Tasks — Iteration 050 (`AUT-07`)

- [x] Implement active 5-vector JWT forgery harness (`alg:none`, `HS256` pubkey confusion, `kid`, `jku`, tampered payload) + `exp <= 86400s` lifetime check in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — `alg:none` and `HS256` key confusion accepted with `HTTP 200`; `exp=None` flagged (`CASA3-AUT-07` x3 in `output/dast-findings.sarif`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 42/61: AUT-07`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-050`, and push `main` + `--tags` to `origin`.

# Tasks — Iteration 041 (`CFG-09`)

- [x] Implement 6 forced-error probes (including oversize 200 KB payload & malformed types) and crawl-wide `4xx`/`5xx` leak inspection in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 8/8 `4xx`/`5xx` responses flagged in `output/dast-findings.sarif`.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 33/61: CFG-09`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-041`, and push `main` + `--tags` to `origin`.

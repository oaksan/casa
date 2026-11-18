# Tasks — Iteration 035 (`CFG-03`)

- [x] Record full crawl HTTP exchanges in `crawled_exchanges` and implement full header+body version/stack disclosure checks in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 4 `CASA3-CFG-03` findings confirmed across 49 HTTP exchanges.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 27/61: CFG-03`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-035`, and push `main` + `--tags` to `origin`.

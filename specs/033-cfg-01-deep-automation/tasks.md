# Tasks — Iteration 033 (`CFG-01`)

- [x] Implement directory prefix spidering, HTML autoindex / S3 `ListBucketResult` parsing, and `output/dast-findings.sarif` emission in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate `CFG-01` against live OWASP Juice Shop (`http://localhost:3000`) — 11 exposed directory indexes detected across 20 probed prefixes.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 25/61: CFG-01`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-033`, and push `main` + `--tags` to `origin`.

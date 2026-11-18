# Tasks — Iteration 047 (`AUT-04`)

- [x] Implement HAR query-string secret redaction, crawl URL/`Referer` inspection, active CWE-598 GET-credential probe, and OAuth `#access_token=` fragment check in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — corrected false PASS to true FAIL (3 `CASA3-AUT-04` findings across 145 requests; 0 plaintext leaks in redacted HAR).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 39/61: AUT-04`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-047`, and push `main` + `--tags` to `origin`.

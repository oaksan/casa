# Tasks — Iteration 051 (`AUT-08`)

- [x] Create `casa-assessment/scripts/headless_storage_dump.js` and integrate real headless Chrome pre/post-logout storage dump + canary/JWT/Luhn checks into `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — confirmed pre-logout `localStorage['token']`, `sessionStorage['bid']`, and `nonHttpOnlyCookies['token']` with `0` post-logout survivors (`CASA3-AUT-08` x3 in `output/dast-findings.sarif`).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 43/61: AUT-08`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-051`, and push `main` + `--tags` to `origin`.

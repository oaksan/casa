# Tasks — Iteration 034 (`CFG-02`)

- [x] Implement 19-endpoint diagnostic probe with SPA anti-false-positive filter and active traceback detection in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 4 `CASA3-CFG-02` exposures confirmed (`/metrics`, `/api-docs/`, `/rest/admin/application-configuration`, HTTP 500 Express `errorhandler` stacktrace).
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 26/61: CFG-02`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-034`, and push `main` + `--tags` to `origin`.

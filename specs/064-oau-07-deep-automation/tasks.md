# Tasks — SDD 064: OAU-07 Deep Automation

- [x] Audit `OAU-07` against `CASA/CASA 3.0 (AL1) Test Guide.md`
- [x] Implement Chrome CDP storage correlation, `Set-Cookie` audit, JS bundle inspection, and mobile preference check in `casa-assessment/casa_audit/scanner.py`
- [x] Validate empirically against live OWASP Juice Shop (`http://localhost:3000`) -> 11 `CASA3-OAU-07` SARIF findings across CDP dump, HTTP cookies, `main.js`, and components
- [x] Document Control 56/61 (`OAU-07`) in `docs/justificativa.txt`
- [x] Update `casa-assessment/tests/test_iteration1.py` & run `unittest`
- [x] Commit, tag `sdd-064`, and push `origin main --tags`

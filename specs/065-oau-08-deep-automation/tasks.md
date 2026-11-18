# Tasks — SDD 065: OAU-08 Deep Automation

- [x] Audit `OAU-08` against `CASA/CASA 3.0 (AL1) Test Guide.md`
- [x] Implement HAR 1.2 `Authorization` transport audit, backend query-token probes, and JS bundle/source inspection in `casa-assessment/casa_audit/scanner.py`
- [x] Validate empirically against live OWASP Juice Shop (`http://localhost:3000`) -> `FAIL` with 4 `CASA3-OAU-08` SARIF findings
- [x] Document Control 57/61 (`OAU-08`) in `docs/justificativa.txt`
- [x] Update `casa-assessment/tests/test_iteration1.py` & run `unittest`
- [x] Commit, tag `sdd-065`, and push `origin main --tags`

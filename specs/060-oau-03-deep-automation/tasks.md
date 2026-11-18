# Tasks — SDD 060: OAU-03 Deep Automation

- [x] Audit `OAU-03` against `CASA/CASA 3.0 (AL1) Test Guide.md`
- [x] Implement full OAuth redirect URI inspection & callback fuzzing (`redirect`, `next`, `continue`, `return_to`, `RelayState`) in `casa-assessment/casa_audit/scanner.py`
- [x] Validate empirically against live OWASP Juice Shop (`http://localhost:3000`) -> 6 `CASA3-OAU-03` SARIF findings across 17 URIs and 33 fuzz probes
- [x] Document Control 52/61 (`OAU-03`) in `docs/justificativa.txt`
- [x] Add assertion in `casa-assessment/tests/test_iteration1.py` and run full `unittest` suite
- [x] Commit, tag `sdd-060`, and push `origin main --tags`

---
description: "Task list for Iteration 73: Guide-Compliant Reference Tooling for Control SCA-03"
---

# Tasks: Iteration 73 — Guide-Compliant Reference Tooling for SCA-03

- [x] T7301 Audit `SCA-03` against `CASA 3.0 (AL1) Test Guide.md` and install official `trivy` binary in `/home/user/.local/bin/trivy`
- [x] T7302 Update `evaluate_sca03_container_os` and `SCA-03` reporting in `casa-assessment/casa_audit/scanner.py` to execute `trivy image` (`JSON` + `SARIF 2.1.0`), filter `will_not_fix`, and export OS packages to `sbom.cdx.json`
- [x] T7303 Add `test_iteration73_sca03_guide_tooling` in `casa-assessment/tests/test_iteration1.py`
- [x] T7304 Document Iteration 73 (`SCA-03`) in `docs/justificativa2.txt`
- [x] T7305 Run unit tests and execute live `POST /api/scan` against OWASP Juice Shop

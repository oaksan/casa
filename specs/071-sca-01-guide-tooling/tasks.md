---
description: "Task list for Iteration 71: Guide-Compliant Reference Tooling for Control SCA-01"
---

# Tasks: Iteration 71 — Guide-Compliant Reference Tooling for SCA-01

- [x] T7101 Audit `SCA-01` against `CASA 3.0 (AL1) Test Guide.md` and install official `syft` and `osv-scanner` binaries in `/home/user/.local/bin/`
- [x] T7102 Implement `syft` CycloneDX 1.5 SBOM generation, `osv-scanner` vulnerability + SARIF execution, transitive dependency reachability, and CISA KEV enforcement for `SCA-01` in `casa-assessment/casa_audit/scanner.py`
- [x] T7103 Update unit tests in `casa-assessment/tests/test_iteration1.py` to verify `syft` and `osv-scanner` integration and transitive reachability for `SCA-01`
- [x] T7104 Document Iteration 71 updates and live OWASP Juice Shop verification results in `docs/justificativa2.txt`
- [x] T7105 Run full unit tests and execute live assessment test against OWASP Juice Shop (`http://localhost:3000` + `/home/user/felipe/speckit/juice-shop-master`)

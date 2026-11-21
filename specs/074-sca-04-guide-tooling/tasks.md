---
description: "Task list for Iteration 74: Guide-Compliant Reference Tooling for Control SCA-04"
---

# Tasks: Iteration 74 — Guide-Compliant Reference Tooling for SCA-04

- [x] T7401 Audit `SCA-04` against `CASA 3.0 (AL1) Test Guide.md` and install `cyclonedx-cli` (`v0.33.1`) in `/home/user/.local/bin/cyclonedx`
- [x] T7402 Implement `cyclonedx validate` and `cyclonedx diff` integration in `evaluate_sca04_sbom_completeness` and `SCA-04` reporting in `casa-assessment/casa_audit/scanner.py`
- [x] T7403 Add `test_iteration74_sca04_guide_tooling` in `casa-assessment/tests/test_iteration1.py`
- [x] T7404 Document Iteration 74 (`SCA-04`) in `docs/justificativa2.txt`
- [x] T7405 Run unit tests, test live `POST /api/scan` against OWASP Juice Shop, commit, tag `sdd-074`, and push to `origin/main`

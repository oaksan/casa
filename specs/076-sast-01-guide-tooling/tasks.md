---
description: "Task list for Iteration 76: Guide-Compliant Reference Tooling for Control SAST-01"
---

# Tasks: Iteration 76 — Guide-Compliant Reference Tooling for SAST-01

- [x] T7601 Audit `SAST-01` against `CASA 3.0 (AL1) Test Guide.md` and install `gitleaks` (`v8.30.1`) in `/home/user/.local/bin/gitleaks`
- [x] T7602 Implement `run_gitleaks_for_sast` and integrate Gitleaks JSON + SARIF 2.1.0 into `evaluate_sast01_secrets_and_entropy` and `run_sast_checks` in `casa-assessment/casa_audit/scanner.py`
- [x] T7603 Add `test_iteration76_sast01_guide_tooling` in `casa-assessment/tests/test_iteration1.py`
- [x] T7604 Document Iteration 76 (`SAST-01`) in `docs/justificativa2.txt`
- [x] T7605 Run unit tests, test live `POST /api/scan` against OWASP Juice Shop, commit, tag `sdd-076`, and push to `origin/main`

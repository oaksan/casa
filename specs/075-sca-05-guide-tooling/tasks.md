---
description: "Task list for Iteration 75: Guide-Compliant Reference Tooling for Control SCA-05"
---

# Tasks: Iteration 75 — Guide-Compliant Reference Tooling for SCA-05

- [x] T7501 Audit `SCA-05` against `CASA 3.0 (AL1) Test Guide.md` (`osv-scanner`, `OpenSSF malicious-packages feed`, Levenshtein-1 typosquatting)
- [x] T7502 Update `evaluate_sca05_malicious_and_typosquat` and `SCA-05` reporting in `casa-assessment/casa_audit/scanner.py` to scan lockfiles & sub-manifests via `osv-scanner`
- [x] T7503 Add `test_iteration75_sca05_guide_tooling` in `casa-assessment/tests/test_iteration1.py`
- [x] T7504 Document Iteration 75 (`SCA-05`) in `docs/justificativa2.txt`
- [x] T7505 Run unit tests, test live `POST /api/scan` against OWASP Juice Shop, commit, tag `sdd-075`, and push to `origin/main`

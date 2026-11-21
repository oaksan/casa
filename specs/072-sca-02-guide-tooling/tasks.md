---
description: "Task list for Iteration 72: Guide-Compliant Reference Tooling for Control SCA-02"
---

# Tasks: Iteration 72 — Guide-Compliant Reference Tooling for SCA-02

- [x] T7201 Audit `SCA-02` against `CASA 3.0 (AL1) Test Guide.md` (`OpenSSF Scorecard`, `endoflife.date`, lockfile registry provenance)
- [x] T7202 Enhance `evaluate_sca02_dependencies` in `casa-assessment/casa_audit/scanner.py` with lockfile exact version resolution, expanded `endoflife.date` coverage (including `express` & `nodejs` engines), and PyPI `OpenSSF Scorecard` / registry provenance checks
- [x] T7203 Add `test_iteration72_sca02_guide_tooling` in `casa-assessment/tests/test_iteration1.py`
- [x] T7204 Document Iteration 72 (`SCA-02`) improvements and OWASP Juice Shop results in `docs/justificativa2.txt`
- [x] T7205 Run unit tests and execute live `POST /api/scan` against OWASP Juice Shop

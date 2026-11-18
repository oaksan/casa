---
description: "Task list for Iteration 9: Deep Automation & Academic Justification for SCA-01"
---

# Tasks: Iteration 9 — Deep Automation & Academic Justification for SCA-01

- [x] T901 Audit `SCA-01` implementation against `CASA 3.0 (AL1) Test Guide.md` and identify reachability, CVSS >= 7.0, CISA KEV, and SARIF 2.1.0 enhancements
- [x] T902 Implement `compute_cvss3_base_score`, `fetch_cisa_kev_set`, `analyze_package_reachability`, and `output/sca-findings.sarif` generation in `casa-assessment/casa_audit/scanner.py`
- [x] T903 Write academic and technical justification for `SCA-01` (with empirical OWASP Juice Shop results) in `docs/justificativa.txt`
- [x] T904 Create SDD Iteration 9 documentation (`spec.md`, `plan.md`, `tasks.md`) in `specs/009-sca-01-deep-automation/`
- [x] T905 Add unit tests for `SCA-01` reachability and CVSS scoring in `casa-assessment/tests/test_iteration1.py`, commit, tag `sdd-009`, and push to `https://github.com/oaksan/casa`

# Implementation Plan: Iteration 9 — Deep Automation & Justification for SCA-01

**Branch**: `[009-sca-01-deep-automation]` | **Date**: 2026-11-18 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/009-sca-01-deep-automation/spec.md)

## Summary

1. Enhance `SCA-01` in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py) with:
   - FIRST.org CVSS v3.1 vector base score calculator (`compute_cvss3_base_score`)
   - CISA Known Exploited Vulnerabilities (`fetch_cisa_kev_set`) catalog integration
   - Source-level Call-Graph / Import Reachability analyzer (`analyze_package_reachability`) tracing imports and method calls (`file:line`) from entry points
   - Dual open-format evidence output (`output/sbom.cdx.json` + `output/sca-findings.sarif`)
2. Document the theoretical basis, audit improvements, and empirical OWASP Juice Shop results for `SCA-01` in [`docs/justificativa.txt`](file:///home/user/felipe/speckit/casa/docs/justificativa.txt).
3. Add unit tests for `compute_cvss3_base_score`, `analyze_package_reachability`, and `sca-findings.sarif` generation in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py), commit, tag `sdd-009`, and push to `https://github.com/oaksan/casa`.

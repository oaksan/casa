# Implementation Plan: Iteration 75 — Guide-Compliant Reference Tooling for SCA-05

**Branch**: `[075-sca-05-guide-tooling]` | **Date**: 2026-11-21 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/075-sca-05-guide-tooling/spec.md)

## Summary

1. Upgrade `evaluate_sca05_malicious_and_typosquat` in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py):
   - Accept optional lockfile `osv_data` from `SCA-01` (`osv-scanner`) to check all direct and transitive dependencies for `MAL-*` and known compromised-maintainer / protestware advisories.
   - Discover sub-manifests (`package.json`, `frontend/package.json`, `ftp/package.json.bak`, `requirements*.txt`) and scan them through `osv-scanner scan source --sbom ... --format json` (with OSV.dev fallback only if `osv-scanner` binary is absent).
   - Keep Levenshtein distance-1 & language-suffix (`-js`, `.js`, `-node`) typosquatting detection with disjoint npm maintainer verification (`fetch_npm_maintainers`).
2. Add `test_iteration75_sca05_guide_tooling` in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py).
3. Document `CONTROLE 05/61: SCA-05 (Iteração SDD 075)` in [`docs/justificativa2.txt`](file:///home/user/felipe/speckit/casa/docs/justificativa2.txt).
4. Run `unittest` and live `POST /api/scan` against OWASP Juice Shop, commit, tag `sdd-075`, and push to `origin/main`.

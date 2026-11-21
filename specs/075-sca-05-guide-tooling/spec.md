# Feature Specification: Iteration 75 — Guide-Compliant Reference Tooling for Control SCA-05

**Feature Branch**: `[075-sca-05-guide-tooling]`

**Created**: 2026-11-21

**Status**: In Progress (Iteration 75)

**Input**: Align control `SCA-05` strictly with `CASA/CASA 3.0 (AL1) Test Guide.md` (`osv-scanner`, `OpenSSF malicious-packages feed`, Levenshtein distance-1 typosquatting under distinct maintainer), validated live against OWASP Juice Shop.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Guide-Compliant Reference Tooling for SCA-05 (Priority: P1)

As a Master's researcher enforcing strict adherence to `CASA 3.0 (AL1) Test Guide.md`, I want control **`SCA-05`** (*"No dependency matches a known-malicious package advisory (typosquat, protestware, compromised maintainer)"*) to execute **`osv-scanner`** backed by the **`OpenSSF malicious-packages feed`** (`MAL-*` and malicious release advisories) across lockfiles (`osv-scanner-sca01.json`) and sub-manifests (`package.json`, `frontend/package.json`, `ftp/package.json.bak`, `requirements*.txt` via CycloneDX manifest scan), combined with Levenshtein distance-1 & suffix typosquatting detection under disjoint npm maintainer sets.

**Acceptance Scenarios**:

1. **Given** a target repository (`juice-shop-master`) with lockfiles and sub-manifests (`frontend/package.json`, `ftp/package.json.bak`), **When** `evaluate_sca05_malicious_and_typosquat` executes, **Then** it scans lockfile + sub-manifest packages through `osv-scanner` for `MAL-*` / malicious advisories and checks Levenshtein distance-1 / suffix typosquats against `registry.npmjs.org` maintainers, writing `CASA3-SCA-05` findings to `output/sca-findings.sarif`.
2. **Given** unit tests and live OWASP Juice Shop scan, **When** validated, **Then** `test_iteration75_sca05_guide_tooling` passes and `eslint-scope@3.7.2`, `ngy-cookie@^6.0.0`, and `epilogue-js@~0.7` are detected accurately in `juice-shop-master`.

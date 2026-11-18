# Feature Specification: Iteration 9 — Deep Automation & Academic Justification for Control SCA-01

**Feature Branch**: `[009-sca-01-deep-automation]`

**Created**: 2026-11-18

**Status**: Implemented (Iteration 9)

**Input**: User request to audit, enhance, and justify control `SCA-01` in `/docs/justificativa.txt` with empirical OWASP Juice Shop results.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Full CASA 3.0 Compliance for Automated Control SCA-01 (Priority: P1)

As a Master's researcher defending the automation of CASA 3.0 AL1 before an academic advisor, I want control **`SCA-01`** to implement all normative steps of the CASA 3.0 AL1 Test Guide — CycloneDX 1.5 SBOM generation, OSV.dev advisory resolution with mathematical CVSS v3.1 base score calculation (`>= 7.0`), CISA KEV catalog cross-checking, static call-graph/import reachability analysis across application entry points, and OASIS SARIF 2.1.0 output (`output/sca-findings.sarif`) — and have its theoretical and empirical justification documented in `/docs/justificativa.txt`.

**Acceptance Scenarios**:

1. **Given** a target repository (`juice-shop-master`), **When** `SCA-01` runs, **Then** it separates blocking findings (`CVSS >= 7.0` AND reachable in call-graph, or `CISA KEV`) from non-blocking informational findings (`CVSS < 7.0` or unreachable CLI devDependencies like `@cyclonedx/cyclonedx-npm`).
2. **Given** the execution of `SCA-01`, **When** artifacts are written to `casa-assessment/output/`, **Then** both `sbom.cdx.json` (CycloneDX 1.5) and `sca-findings.sarif` (OASIS SARIF 2.1.0) are generated.
3. **Given** `/docs/justificativa.txt`, **When** reviewed for the Master's presentation, **Then** it documents the CASA 3.0 normative basis, the improvements implemented in Iteration 9, and the exact OWASP Juice Shop results (11 blocking vs. 5 non-blocking packages).

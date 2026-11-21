# Feature Specification: Iteration 74 — Guide-Compliant Reference Tooling for Control SCA-04

**Feature Branch**: `[074-sca-04-guide-tooling]`

**Created**: 2026-11-21

**Status**: In Progress (Iteration 74)

**Input**: Align control `SCA-04` strictly with `CASA/CASA 3.0 (AL1) Test Guide.md` (`syft`, `cyclonedx-cli`) for validating published CycloneDX 1.5+ / SPDX 2.3+ SBOMs, NTIA minimum elements, schema validation, and structural diff `(Assessor_SBOM − Published_SBOM)`, validated live against OWASP Juice Shop.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Guide-Compliant Reference Tooling for SCA-04 (Priority: P1)

As a Master's researcher enforcing strict adherence to `CASA 3.0 (AL1) Test Guide.md`, I want control **`SCA-04`** (*"A complete, machine-readable SBOM is published for the assessed build, and it matches an SBOM the assessor generates independently"*) to use the official free/open-source reference tools listed in the guide — **`syft`** (assessor SBOM generation in `output/sbom.cdx.json`) and **`cyclonedx-cli`** (`cyclonedx validate` for formal CycloneDX 1.5+ schema validation + `cyclonedx diff` saving `output/cyclonedx-diff.json`), combined with NTIA Minimum Elements verification and normalized `(Assessor_SBOM − Published_SBOM)` set-difference checks.

**Acceptance Scenarios**:

1. **Given** a target repository and/or built container image (`bkimminich/juice-shop:latest:/juice-shop/bom.json`), **When** `evaluate_sca04_sbom_completeness` runs, **Then** it runs `cyclonedx validate` against the declared CycloneDX specVersion (>= 1.5), validates NTIA Minimum Elements, executes `cyclonedx diff` producing `output/cyclonedx-diff.json`, and checks `(Assessor_SBOM − Published_SBOM)`.
2. **Given** a valid, matching CycloneDX 1.5 published SBOM in unit tests, **When** `evaluate_sca04_sbom_completeness` runs, **Then** `cyclonedx validate` passes and `SCA-04` returns `PASS`.
3. **Given** unit tests and live scan against OWASP Juice Shop, **When** validated, **Then** `test_iteration74_sca04_guide_tooling` passes and live `POST /api/scan` confirms all findings and artifacts (`sbom.cdx.json`, `cyclonedx-diff.json`, `sca-findings.sarif`).

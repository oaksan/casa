# Feature Specification: Iteration 73 — Guide-Compliant Reference Tooling for Control SCA-03

**Feature Branch**: `[073-sca-03-guide-tooling]`

**Created**: 2026-11-21

**Status**: In Progress (Iteration 73)

**Input**: Align control `SCA-03` strictly with `CASA/CASA 3.0 (AL1) Test Guide.md` (`trivy` / `grype`) for scanning container base images and OS packages, including unfixed vulnerabilities (`will_not_fix` filtering) and SARIF 2.1.0 + CycloneDX 1.5 evidence output, validated against OWASP Juice Shop.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Guide-Compliant Reference Tooling for SCA-03 (Priority: P1)

As a Master's researcher enforcing strict adherence to `CASA 3.0 (AL1) Test Guide.md`, I want control **`SCA-03`** (*"Container base images and OS packages contain no unmitigated Critical/High CVEs"*) to use the official free/open-source reference tool **`trivy`** (`v0.76.2`) against declared container images and `Dockerfile` stages:
1. Scan container OS packages and base layers via **`trivy image --pkg-types os --severity HIGH,CRITICAL`** (supporting `DOCKER_API_VERSION=1.44`, unfixed advisories included, and extracting OS package inventory into CycloneDX 1.5 `output/sbom.cdx.json` via `--list-all-pkgs` / Syft).
2. Inspect `Status` (`will_not_fix`, `unimportant`, `end_of_life`) per distribution metadata so that `PASS`/`FAIL` enforces exact CASA 3.0 criteria (zero unmitigated HIGH/CRITICAL OS CVEs not marked `will_not_fix`), alongside unpinned `Dockerfile` base-image digest checks (`@sha256:`).
3. Emit native **`output/trivy-sca03.sarif`** (`SARIF 2.1.0`) and consolidated `CASA3-SCA-03` findings in `output/sca-findings.sarif`.

**Acceptance Scenarios**:

1. **Given** a target repository with a `Dockerfile` and local container image (`bkimminich/juice-shop:latest`), **When** `evaluate_sca03_container_os` runs, **Then** it invokes `trivy` (`--pkg-types os`), separates unmitigated HIGH/CRITICAL OS CVEs from `will_not_fix` advisories, checks `Dockerfile` `@sha256:` pinning, populates `sbom.cdx.json` with OS packages, and writes `trivy-sca03.sarif` + `sca-findings.sarif`.
2. **Given** unit tests and live scan against OWASP Juice Shop, **When** validated, **Then** `test_iteration73_sca03_guide_tooling` passes and `POST /api/scan` reports real `Trivy` results on `bkimminich/juice-shop:latest`.

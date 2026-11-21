# Feature Specification: Iteration 71 — Guide-Compliant Reference Tooling for Control SCA-01

**Feature Branch**: `[071-sca-01-guide-tooling]`

**Created**: 2026-11-21

**Status**: In Progress (Iteration 71)

**Input**: Align control `SCA-01` strictly with the reference tooling specified in `CASA/CASA 3.0 (AL1) Test Guide.md` (`syft`, `osv-scanner`, `NVD / OSV.dev / CISA KEV feeds`) and validate end-to-end against OWASP Juice Shop.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Guide-Compliant Reference Tooling for SCA-01 (Priority: P1)

As a Master's researcher enforcing strict adherence to `CASA 3.0 (AL1) Test Guide.md`, I want control **`SCA-01`** to execute the exact free/open-source reference tools listed in the guide — **`syft`** for assessor CycloneDX 1.5+ SBOM generation across direct and transitive lockfiles, and **`osv-scanner`** (backed by **`NVD / OSV.dev`** feeds) combined with **`CISA KEV`** cross-checking and source/dependency-graph reachability analysis — producing `CycloneDX 1.5` (`output/sbom.cdx.json`) and `SARIF 2.1.0` (`output/sca-findings.sarif`, `output/osv-scanner.sarif`) and validated against OWASP Juice Shop.

**Acceptance Scenarios**:

1. **Given** a target repository (`juice-shop-master` with `package-lock.json` or any repo with lockfiles/manifests), **When** `run_sca_checks` executes `SCA-01`, **Then** it invokes `syft` to generate `output/sbom.cdx.json` (`CycloneDX 1.5`) and `osv-scanner` to scan dependencies (direct and transitive) against OSV.dev / NVD advisories.
2. **Given** vulnerability findings from `osv-scanner`, **When** `SCA-01` evaluates blocking criteria, **Then** it checks CVSS v3.1 base score (`>= 7.0`), evaluates reachability (direct source entry-point imports/calls and transitive dependency paths via the Syft SBOM `dependencies` graph / lockfile), and cross-checks CVE aliases against `CISA KEV`.
3. **Given** `SCA-01` completion, **When** artifacts and logs are inspected, **Then** `output/sca-findings.sarif` contains `error`-level SARIF 2.1.0 entries only for blocking findings (`CVSS >= 7.0` and reachable, or `CISA KEV`), non-blocking items are omitted from the `SCA-01` log, and all unit tests plus live OWASP Juice Shop scans pass cleanly.

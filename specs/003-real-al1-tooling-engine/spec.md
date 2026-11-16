# Feature Specification: Iteration 3 — Real AL1 Tooling & Active DAST/SAST/SCA Engine

**Feature Branch**: `[003-real-al1-tooling-engine]`

**Created**: 2026-11-16

**Status**: Implemented (Iteration 3)

**Input**: User request to audit and replace MVP placeholders in AL1 with real tool execution (`Semgrep` AST + SARIF 2.1.0, `OSV.dev` batch vulnerability queries + CycloneDX 1.5 SBOM, and multi-route active HTTP/TLS/DAST/Auth/OAuth probes + W3C HAR 1.2 capture).

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Real Multi-Tool AL1 Execution Pipeline (Priority: P1)

As a security researcher evaluating a web application (such as OWASP Juice Shop) against the **61 CASA 3.0 AL1 controls**, I want the scanner engine to execute real static analysis (`semgrep`), real dependency vulnerability lookups (`OSV.dev` API + CycloneDX SBOM generation), and real active HTTP/TLS/Auth/Injection probes (with W3C HAR 1.2 recording), so that every `PASS` and `FAIL` verdict is backed by genuine empirical evidence rather than fast MVP placeholders.

**Why this priority**: Essential for scientific validity in the Master's thesis evaluation.

**Acceptance Scenarios**:

1. **Given** `repo_path="/home/user/felipe/speckit/juice-shop-master"`, **When** Domain 1 (`SCA-01..05`) runs, **Then** it parses `package.json` / `Dockerfile`, writes `casa-assessment/output/sbom.cdx.json` (CycloneDX 1.5), queries `https://api.osv.dev/v1/querybatch`, and accurately detects vulnerable and EOL packages (`SCA-01`, `SCA-02`, `SCA-03`, `SCA-04`).
2. **Given** `repo_path="/home/user/felipe/speckit/juice-shop-master"`, **When** Domain 2 (`SAST-01..13`) runs, **Then** it invokes `/home/user/.local/bin/semgrep` with `casa-assessment/rules/casa3_al1_sast.yml`, writes `casa-assessment/output/semgrep-sast.sarif` (SARIF 2.1.0), and maps AST findings (`file:line`) to `SAST-01..13`.
3. **Given** `target_url="http://localhost:3000"`, **When** Domains 3–7 (`TLS`, `CFG`, `AUT`, `AZI`, `OAU`) run, **Then** active HTTP probes test `/`, `/ftp`, `/metrics`, `/rest/products/search?q='`, `/rest/admin/application-configuration`, `/rest/user/login`, and `/ftp/package.json.bak%2500.md`, writing `casa-assessment/output/dast-capture.har` (W3C HAR 1.2) and reporting real vulnerabilities.

# Feature Specification: Iteration 11 — Deep Automation & Academic Justification for Control SCA-03

**Feature Branch**: `[011-sca-03-deep-automation]`

**Created**: 2026-11-18

**Status**: Implemented (Iteration 11)

**Input**: User request to implement SDD Iteration 11 auditing, enhancing, and justifying control `SCA-03` in `/docs/justificativa.txt` with empirical OWASP Juice Shop results.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Full CASA 3.0 Compliance for Automated Control SCA-03 (Priority: P1)

As a Master's researcher defending the automation of CASA 3.0 AL1, I want control **`SCA-03`** (*"Container base images and OS packages contain no unmitigated Critical/High CVEs"*) to inspect the container image digest and `Dockerfile`, extract all installed OS packages (`/var/lib/dpkg/status.d`), query the distribution's vulnerability feed (`Debian:13` on OSV.dev) including vulnerabilities without published fixes, filter out advisories marked `unimportant` / `will_not_fix` by the distribution, and report all unmitigated HIGH/CRITICAL (`CVSS >= 7.0`) OS vulnerabilities in `output/sbom.cdx.json` and `output/sca-findings.sarif`.

**Acceptance Scenarios**:

1. **Given** a target repository with a `Dockerfile` and container image (`juice-shop-master`), **When** `SCA-03` runs, **Then** it extracts the 14 Debian 13 OS packages, queries OSV.dev, separates blocking HIGH/CRITICAL OS CVEs from non-blocking (`CVSS < 7.0` or `urgency=unimportant`) advisories, and writes `CASA3-SCA-03` findings to `output/sca-findings.sarif`.
2. **Given** `/docs/justificativa.txt`, **When** updated in Iteration 11, **Then** it includes a complete section for `CONTROLE 03/61: SCA-03` with CASA 3.0 normative grounding and empirical OWASP Juice Shop results.

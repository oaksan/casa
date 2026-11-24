# Feature Specification 119 — AZI-06 Guide-Compliant Tooling (`OWASP ZAP 20019/20014` + `NoRedirect Open-Redirect & HPP Differential Harness`)

## Control Covered
- **ID:** `AZI-06`
- **Title:** No open redirect or unvalidated forward; HTTP parameter pollution handled safely
- **External Reference:** ASVS V5.1.5, V5.1.1 (L1); CWE-601 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** **OWASP ZAP** active rules `20019` (*External Redirect*) & `20014` (*HTTP Parameter Pollution*) + authenticated **NoRedirect Open-Redirect & HPP Authorization Differential Harness** (checking 3xx `Location`, `<meta http-equiv="refresh">`, JS redirect targets against strict hostname allowlists, and duplicated authorization parameters), producing SARIF 2.1.0 (`CASA3-AZI-06`), structured JSON (`output/azi06-redirect-hpp-audit.json`), and redacted HAR 1.2 (`output/azi06-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Zero OWASP ZAP `20019`/`20014` alerts, zero 3xx/meta-refresh/JS redirects resolving outside allowlisted hosts, and zero authorization-outcome changes caused by duplicated parameters.
  - **FAIL:** `>= 1` off-allowlist redirect, ZAP `20019`/`20014` alert, or duplicated-parameter authorization flip.

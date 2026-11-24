# Feature Specification 115 — AZI-02 Guide-Compliant Tooling (`OWASP ZAP Active XSS 40012/40014` + `Headless Chrome OOB Callback Harness`)

## Control Covered
- **ID:** `AZI-02`
- **Title:** No Cross-Site Scripting — reflected, stored or DOM-based
- **External Reference:** ASVS V5.3.3 (L1); CWE-79 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** **OWASP ZAP** active XSS scan (Policy rules `40012` Cross Site Scripting Reflected & `40014` Cross Site Scripting Persistent) + **Headless Chrome CDP** DOM/Stored/Reflected active XSS probe suite (`scripts/headless_xss_callback.js`) with live **out-of-band HTTP callback confirmation**, outputting SARIF 2.1.0 (`CASA3-AZI-02`), JSON audit report (`output/azi02-xss-audit.json`), and redacted HAR 1.2 (`output/azi02-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Zero XSS executions confirmed by out-of-band HTTP callback, zero OWASP ZAP active XSS (`40012`/`40014`) findings, and zero reproducible unescaped HTML/DOM candidate sinks.
  - **FAIL:** `>= 1` out-of-band execution callback triggered in headless browser **or** confirmed ZAP active XSS / unescaped HTML reflection.

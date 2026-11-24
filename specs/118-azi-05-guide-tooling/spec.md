# Feature Specification 118 — AZI-05 Guide-Compliant Tooling (`OWASP ZAP 6/7` + `LFI/Traversal & RFI Matrix Harness`)

## Control Covered
- **ID:** `AZI-05`
- **Title:** No Local/Remote File Inclusion or path traversal
- **External Reference:** ASVS V5.3.9, V12.3.2, V12.3.3 (L1); CWE-22, CWE-98 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** **OWASP ZAP** active rules `6` (*Path Traversal*) & `7` (*Remote File Inclusion*) + authenticated **LFI/Path Traversal & RFI harness** covering encoded, double-encoded, null-byte, absolute, and UNC path forms plus ephemeral HTTP callback/inclusion marker checks, producing SARIF 2.1.0 (`CASA3-AZI-05`), structured JSON (`output/azi05-lfi-rfi-audit.json`), and redacted HAR 1.2 (`output/azi05-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Zero OWASP ZAP `6`/`7` alerts, zero responses returning content from outside the document root or restricted files, and zero remote file inclusion callbacks or markers.
  - **FAIL:** `>= 1` ZAP `6`/`7` finding, out-of-root file content returned, or remote inclusion callback/marker observed.

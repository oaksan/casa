# SDD Iteration 053 Spec: AZI-02 Deep Automation

## Control Under Audit
- **ID:** `AZI-02`
- **Requirement:** No Cross-Site Scripting — reflected, stored or DOM-based (`OWASP ASVS V5.3.3 (L1); CWE-79`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner relied solely on static `bypassSecurityTrustHtml` grep (even matching `.spec.ts` files) without running an active XSS scan or browser execution callback.
2. Lacked an ephemeral out-of-band HTTP callback listener, stored/reflected payload seeding, headless Chrome DOM traversal, and `CASA3-AZI-02` SARIF 2.1.0 reporting.

## Requirements
- Spin up an ephemeral local HTTP callback server (`XssCallbackHandler` on `127.0.0.1:0`), seed stored/reflected XSS probes (`POST /api/Feedbacks/`, `POST /profile`, `GET /rest/products/search`), and drive headless Chrome (`casa-assessment/scripts/headless_xss_callback.js`) with authenticated cookie across `/#/about`, `/#/search?q=<img onerror=fetch(...)>`, and `/profile`.
- Filter `.spec.ts` test mocks from static sink count (7 real Angular components) and fail with `out_of_band_http_callback` proof when live JS executes.
- Emit `CASA3-AZI-02` results to `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

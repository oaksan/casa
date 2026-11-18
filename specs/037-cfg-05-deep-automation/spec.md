# SDD Iteration 037 Spec: CFG-05 Deep Automation

## Control Under Audit
- **ID:** `CFG-05`
- **Requirement:** Clickjacking prevented via `frame-ancestors` or `X-Frame-Options` (`OWASP ASVS V14.4.7 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only evaluated `root_headers` (`GET /`) instead of 100% of HTML responses across the crawl.
2. Substring check `"frame-ancestors" in csp.lower()` did not reject unsafe wildcards like `frame-ancestors *`.
3. Missing `CASA3-CFG-05` SARIF 2.1.0 findings and artifact pointers.

## Requirements
- Inspect every HTML route in `html_routes_seen`.
- Require `X-Frame-Options` in `{"DENY", "SAMEORIGIN"}` OR parsed CSP `frame-ancestors` with `'none'`, `'self'`, or explicit origin list (rejecting `*` or empty directives).
- Emit `CASA3-CFG-05` results to `output/dast-findings.sarif` alongside `output/dast-capture.har`.

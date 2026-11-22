# Feature Specification 099 — CFG-05 Guide-Compliant Tooling (`OWASP ZAP`)

## Control Covered
- **ID:** `CFG-05`
- **Title:** Clickjacking prevented via `frame-ancestors` or `X-Frame-Options`
- **External Reference:** ASVS V14.4.7 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** OWASP ZAP `2.17.0` (Spider + Passive Scan Rule `10020` — *Missing Anti-clickjacking Header*, open-source counterpart to Burp Suite) + Multi-Route HTML Header & CSP `frame-ancestors` Parser.
- **Evidence:** DAST findings in SARIF 2.1.0 (`dast-findings.sarif`), ZAP SARIF/JSON (`zap-findings.sarif`, `zap-report.json`), and HTTP HAR 1.2 (`dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Every HTML response carries `frame-ancestors` (`'none'`, `'self'`, or explicit origin list without `*`) or `X-Frame-Options: DENY` / `SAMEORIGIN`, with zero uncovered ZAP `10020` violations.
  - **FAIL:** `>= 1` HTML response lacks both valid `X-Frame-Options` and valid CSP `frame-ancestors`.

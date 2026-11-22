# Feature Specification 100 — CFG-06 Guide-Compliant Tooling (`OWASP ZAP`)

## Control Covered
- **ID:** `CFG-06`
- **Title:** `X-Content-Type-Options: nosniff` on all responses
- **External Reference:** ASVS V14.4.4 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** OWASP ZAP `2.17.0` (Spider + Passive Scan Rule `10021` — *X-Content-Type-Options Header Missing*, open-source counterpart to Burp Suite) + 100% Crawl Header Inspector.
- **Evidence:** DAST findings in SARIF 2.1.0 (`dast-findings.sarif`), ZAP SARIF/JSON (`zap-findings.sarif`, `zap-report.json`), and HTTP HAR 1.2 (`dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** `X-Content-Type-Options: nosniff` present on **100%** of valid HTTP responses across the crawl and zero unmitigated ZAP `10021` findings.
  - **FAIL:** Present on fewer than **100%** of HTTP responses.

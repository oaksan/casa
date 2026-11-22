# Feature Specification 101 — CFG-07 Guide-Compliant Tooling (`OWASP ZAP`)

## Control Covered
- **ID:** `CFG-07`
- **Title:** Anti-caching headers on all authenticated and sensitive responses
- **External Reference:** ASVS V8.2.1 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** OWASP ZAP `2.17.0` (Passive Scan Rules `10049` *Storable and Cacheable Content* & `10015` *Re-examine Cache-control Directives*, open-source counterpart to Burp Suite) + Authenticated Multi-Route `Cache-Control: no-store` Inspector.
- **Evidence:** DAST findings in SARIF 2.1.0 (`dast-findings.sarif`), ZAP SARIF/JSON (`zap-findings.sarif`, `zap-report.json`), and HTTP HAR 1.2 (`dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Every authenticated and sensitive 2xx response carries strict `Cache-Control` including `no-store`.
  - **FAIL:** `>= 1` authenticated/sensitive 2xx response omits `no-store` (including `private`-only or missing headers).

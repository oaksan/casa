# Feature Specification 102 — CFG-08 Guide-Compliant Tooling (`OWASP ZAP`)

## Control Covered
- **ID:** `CFG-08`
- **Title:** CORS uses a strict allow list; no wildcard with credentials; no unvalidated origin reflection
- **External Reference:** ASVS V14.5.3 (L1); CWE-942 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** OWASP ZAP `2.17.0` (Passive Scan Rule `10098` *Cross-Domain Misconfiguration*, open-source counterpart alongside Burp Suite / Schemathesis) + Multi-Origin Active CORS Allowlist Probe (`foreign_origin`, `null_origin`, `suffix_sharing_origin`).
- **Evidence:** DAST findings in SARIF 2.1.0 (`dast-findings.sarif`), ZAP SARIF/JSON (`zap-findings.sarif`, `zap-report.json`), and HTTP HAR 1.2 (`dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** No probe origin is reflected in `Access-Control-Allow-Origin`; no `*` combined with `Access-Control-Allow-Credentials: true`; `null` origin is not accepted; no permissive wildcard CORS on sensitive endpoints or unmitigated ZAP `10098` cross-domain alerts on API/sensitive routes.
  - **FAIL:** Any probe origin reflected, `null` accepted, wildcard with credentials, or permissive `*` on sensitive endpoints.

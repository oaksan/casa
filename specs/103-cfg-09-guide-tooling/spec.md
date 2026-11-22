# Feature Specification 103 — CFG-09 Guide-Compliant Tooling (`OWASP ZAP`)

## Control Covered
- **ID:** `CFG-09`
- **Title:** 4xx/5xx responses return generic messages; no stack traces, internal paths or routing detail
- **External Reference:** ASVS V7.4.1 (L1); CWE-209 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** OWASP ZAP `2.17.0` (Passive Scan Rule `90022` *Application Error Disclosure*, open-source counterpart alongside Burp Suite / Schemathesis) + Malformed-Type, Oversize-Body (413), and Forced-Error Active Probes across Crawl `4xx`/`5xx` Responses.
- **Evidence:** DAST findings in SARIF 2.1.0 (`dast-findings.sarif`), ZAP SARIF/JSON (`zap-findings.sarif`, `zap-report.json`), and HTTP HAR 1.2 (`dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Zero `4xx`/`5xx` bodies disclose stack frames, file-system paths, SQL fragments, or internal module/routing details, and zero ZAP `90022` error-disclosure alerts match.
  - **FAIL:** `>= 1` `4xx`/`5xx` body discloses any of those elements or triggers ZAP `90022`.

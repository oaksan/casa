# Feature Specification 104 — CFG-10 Guide-Compliant Tooling (`OWASP ZAP` + `SecLists`)

## Control Covered
- **ID:** `CFG-10`
- **Title:** No administrative interface reachable without authentication
- **External Reference:** CWE-306; *ADA-defined* | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** OWASP ZAP `2.17.0` (Spider / Discovery URL Inventory + Hidden/Config Alerts `40035`/`10033`, open-source counterpart alongside Burp Suite) + SecLists curated administrative/operations wordlist (`rules/seclists_cfg10_admin.txt`) with Authenticated vs Unauthenticated Differential Replay (`LCS >= 0.90`).
- **Evidence:** DAST findings in SARIF 2.1.0 (`dast-findings.sarif`), ZAP SARIF/JSON (`zap-findings.sarif`, `zap-report.json`), and HTTP HAR 1.2 (`dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Every route in the authenticated set is denied when replayed without credentials, and zero SecLists administrative/wordlist paths return unauthenticated `2xx` with LCS line similarity `>= 0.90` to their authenticated response.
  - **FAIL:** `>= 1` authenticated route accepted unauthenticated or `>= 1` administrative wordlist path returns unauthenticated `2xx` with `LCS >= 0.90`.

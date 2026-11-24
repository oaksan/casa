# Feature Specification 117 — AZI-04 Guide-Compliant Tooling (`OWASP ZAP 90020` + `Out-of-Band HTTP/DNS Callback Harness`)

## Control Covered
- **ID:** `AZI-04`
- **Title:** No OS command injection
- **External Reference:** ASVS V5.3.8 (L1); CWE-78 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** **OWASP ZAP** active OS Command Injection (`90020`) + authenticated multi-parameter OS command-injection harness with live **out-of-band HTTP and UDP DNS callback listeners** + direct shell output marker detection (`uid=`, `root:x:0:0:`, Windows markers), emitting SARIF 2.1.0 (`CASA3-AZI-04`), structured JSON (`output/azi04-cmdi-audit.json`), and redacted HAR 1.2 (`output/azi04-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Zero out-of-band HTTP/DNS callbacks received, zero OWASP ZAP OS command-injection alerts (`90020`), and zero command-output markers in any response.
  - **FAIL:** `>= 1` out-of-band HTTP/DNS callback, ZAP command-injection alert, or command-output marker in a response.

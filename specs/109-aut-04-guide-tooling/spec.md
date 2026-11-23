# Feature Specification 109 — AUT-04 Guide-Compliant Tooling (`OWASP ZAP 3/10024/10025` + `HAR URL/Query/Fragment/Referer Inspector`)

## Control Covered
- **ID:** `AUT-04`
- **Title:** Session tokens and credentials never appear in URLs, query strings or `Referer`
- **External Reference:** ASVS V3.1.1 (L1); CWE-598 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** **OWASP ZAP** (Passive rules `3` Session ID in URL Rewrite, `10024` Sensitive Information in URL, `10025` Sensitive Information in HTTP Referrer Header) + authenticated crawl/HAR URL, query string, fragment, `Location` redirect, and outbound request `Referer` inspector + CWE-598 GET credential probe, outputting SARIF 2.1.0 (`CASA3-AUT-04`) and redacted HAR 1.2 (`output/aut04-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** No session, access, or refresh token value or credential appears in any request URL, query string, fragment, redirect `Location`, or outbound `Referer`, and ZAP rules `3`/`10024`/`10025` + GET-credential probes find zero leaks.
  - **FAIL:** `>= 1` token or credential exposure detected in URLs, query strings, fragments, outbound `Referer` headers, redirects, or accepted GET credential endpoints.

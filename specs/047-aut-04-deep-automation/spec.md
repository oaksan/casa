# SDD Iteration 047 Spec: AUT-04 Deep Automation

## Control Under Audit
- **ID:** `AUT-04`
- **Requirement:** Session tokens and credentials never appear in URLs, query strings or `Referer` (`OWASP ASVS V3.1.1 (L1); CWE-598`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner returned a static hardcoded `PASS` stub without scanning captured HAR requests or `Referer` headers.
2. Never tested whether authentication/account endpoints accept credentials via GET query strings (`GET /rest/user/change-password`) or transfer `#access_token=` in URL fragments.
3. Sensitive query-string parameters were not redacted in `output/dast-capture.har`, and `CASA3-AUT-04` SARIF 2.1.0 entries were missing.

## Requirements
- Redact sensitive query parameters (`current`, `new`, `repeat`, `password`, `token`, `access_token`, `refresh_token`) in `har_entries` URLs (`[REDACTED]`).
- Scan all `crawled_exchanges` URLs, query strings, fragments, and `Referer` headers for active session tokens, JWTs, and credential parameters.
- Probe `GET /rest/user/change-password` (CWE-598) with ephemeral account credentials and inspect OAuth fragment routes (`#access_token=`), emitting `CASA3-AUT-04` findings into `output/dast-findings.sarif`.

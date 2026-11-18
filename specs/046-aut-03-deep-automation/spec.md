# SDD Iteration 046 Spec: AUT-03 Deep Automation

## Control Under Audit
- **ID:** `AUT-03`
- **Requirement:** A new session token is issued upon authentication (session fixation prevented) (`OWASP ASVS V3.2.1 (L1); CWE-384`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only checked `bool(jwt_token)` without capturing pre-authentication session identifiers or injecting fixation cookies into login.
2. Never replayed pre-authentication session identifiers against authenticated endpoints after login.
3. Missing `CASA3-AUT-03` SARIF 2.1.0 emission and redacted HAR 1.2 artifact links.

## Requirements
- Capture any pre-authentication `Set-Cookie` values from `/` and `/rest/user/whoami`, inject fixation cookies (`token`, `connect.sid`, `JSESSIONID`) on login, verify post-login token rotation (`post != pre`), and replay pre-authentication IDs against `/rest/wallet/balance` and `/rest/basket/{bid}`.
- Emit `CASA3-AUT-03` findings into `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

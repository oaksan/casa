# Feature Specification 108 — AUT-03 Guide-Compliant Tooling (`Session Fixation & Post-Auth Replay Harness`)

## Control Covered
- **ID:** `AUT-03`
- **Title:** A new session token is issued upon authentication (session fixation prevented)
- **External Reference:** ASVS V3.2.1 (L1); CWE-384 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Scripted pre-auth capture + login fixation + post-auth replay harness outputting SARIF 2.1.0 (`CASA3-AUT-03`) and redacted HAR 1.2 captures (`output/aut03-replayed.har` + `output/dast-capture.har`).
- **Test Procedure:**
  1. Probe pre-authentication routes (`/`, `/rest/user/whoami`) and record any issued `Set-Cookie` session identifiers.
  2. Authenticate (`POST /rest/user/login`) while presenting captured pre-authentication identifiers plus injected fixation cookies (`token`, `connect.sid`, `JSESSIONID`), capturing all post-authentication token/cookie identifiers.
  3. Replay every pre-authentication and fixed identifier against protected routes (`/rest/wallet/balance`, `/rest/basket/{bid}`) after authentication.
- **Verification Criteria:**
  - **PASS:** Post-authentication session identifier(s) differ from all pre-authentication / fixation identifiers, **and** every replay of a pre-authentication identifier against protected routes is rejected (`401`/`403`/non-2xx).
  - **FAIL:** Any session identifier remains unchanged / adopted from pre-auth across login, **or** any pre-authentication / fixed identifier remains accepted (`2xx`) on a protected route after authentication.

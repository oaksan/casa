# Feature Specification 110 — AUT-05 Guide-Compliant Tooling (`Post-Logout Session & Refresh Replay Harness`)

## Control Covered
- **ID:** `AUT-05`
- **Title:** Logout invalidates the session server-side, including refresh tokens
- **External Reference:** ASVS V3.3.1 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Scripted post-logout session and refresh token replay harness outputting SARIF 2.1.0 (`CASA3-AUT-05`) and redacted HAR 1.2 capture (`output/aut05-replayed.har` + `output/dast-capture.har`).
- **Test Procedure:**
  1. Authenticate to obtain fresh session token/cookie and optional refresh token.
  2. Invoke server logout endpoints (filtering SPA catch-all responses).
  3. Replay both the captured session token/cookie against protected routes and any captured refresh token against token refresh endpoints.
- **Verification Criteria:**
  - **PASS:** Both the replayed session token/cookie and the replayed refresh token are rejected (`401`/`403`/non-2xx) after logout.
  - **FAIL:** Either the session token/cookie **or** the refresh token remains accepted after logout (including stateless JWT signing without revocation).

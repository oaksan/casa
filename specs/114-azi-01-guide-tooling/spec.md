# Feature Specification 114 — AZI-01 Guide-Compliant Tooling (`3-Mode Anti-CSRF Replay & Re-Read Harness`)

## Control Covered
- **ID:** `AZI-01`
- **Title:** Strong anti-CSRF mechanism on all state-changing authenticated functionality
- **External Reference:** ASVS V4.2.2 (L1); CWE-352 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Scripted authenticated differential anti-CSRF harness executing 3 replay modes (`csrf_token_removed`, `csrf_token_replaced`, `csrf_token_second_session` with genuine Session B CSRF extraction), verifying re-read persistence on the target state endpoint and auditing `Set-Cookie` headers for `SameSite=None`, outputting SARIF 2.1.0 (`CASA3-AZI-01`) and redacted HAR 1.2 (`output/azi01-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** All 3 anti-CSRF replay modes are denied with zero observable state change on re-read, and no session cookie uses `SameSite=None`.
  - **FAIL:** `>= 1` state-changing replay succeeds without a valid session-bound anti-CSRF token (removed, replaced, or cross-session), or any session cookie uses `SameSite=None`.

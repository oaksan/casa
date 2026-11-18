# SDD Iteration 048 Spec: AUT-05 Deep Automation

## Control Under Audit
- **ID:** `AUT-05`
- **Requirement:** Logout invalidates the session server-side, including refresh tokens (`OWASP ASVS V3.3.1 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner relied strictly on static substring checks inside `lib/insecurity.ts` without executing dynamic logout HTTP probes or post-logout token replay.
2. Lacked SPA catch-all filtering on `/logout` routes, refresh-token replay probes, and `CASA3-AUT-05` SARIF 2.1.0 entries.

## Requirements
- Invoke candidate logout endpoints (`POST`/`GET /rest/user/logout`, `/api/logout`, `/auth/logout`, `/logout`, `/rest/saveLoginIp`) with SPA catch-all detection.
- Replay the captured session token/cookie (and refresh token when present) against `/rest/wallet/balance`, `/rest/basket/{bid}`, and `/rest/user/whoami` after logout.
- Fail whenever any protected route accepts the post-logout token, emitting `CASA3-AUT-05` findings into `output/dast-findings.sarif`.

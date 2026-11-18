# SDD Iteration 039 Spec: CFG-07 Deep Automation

## Control Under Audit
- **ID:** `CFG-07`
- **Requirement:** Anti-caching headers on all authenticated and sensitive responses (`OWASP ASVS V8.2.1 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner probed `/rest/user/whoami` unauthenticated only and fell back to `/`.
2. Erroneously accepted `private` instead of strictly requiring `Cache-Control: no-store`.
3. Missing coverage across authenticated user/financial routes and missing `CASA3-CFG-07` SARIF 2.1.0 entries.

## Requirements
- Provision/login an authenticated session (`Authorization: Bearer` + `Cookie: token=...`).
- Probe 9 authenticated/sensitive routes (`/rest/user/whoami`, `/rest/basket/{bid}`, `/api/Users/{uid}`, `/rest/wallet/balance`, `/api/Cards`, `/rest/2fa/status`, `/rest/admin/application-configuration`, `/support/logs`, `/encryptionkeys`).
- Fail unless every 2xx response carries strict `no-store` directive in `Cache-Control`, emitting `CASA3-CFG-07` to `output/dast-findings.sarif`.

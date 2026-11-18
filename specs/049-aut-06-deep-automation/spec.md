# SDD Iteration 049 Spec: AUT-06 Deep Automation

## Control Under Audit
- **ID:** `AUT-06`
- **Requirement:** Session cookies set `Secure`, `HttpOnly` and `SameSite` (`Lax` or `Strict`) (`OWASP ASVS V3.4.1, V3.4.2, V3.4.3 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only inspected `l_hdrs` + `root_headers` with a substring `"samesite"` check (which failed to reject `SameSite=None`).
2. Did not scan all `Set-Cookie` headers across `crawled_exchanges`, verify backend session-cookie consumption, or inspect client-side JS session cookie setting.
3. Missing `CASA3-AUT-06` SARIF 2.1.0 entries in `output/dast-findings.sarif`.

## Requirements
- Parse every `Set-Cookie` header across `crawled_exchanges` requiring `Secure`, `HttpOnly`, and strict `SameSite=Lax|Strict`.
- Probe backend cookie authentication and detect client-side `cookieService.put('token', ...)` cookie writes lacking `HttpOnly`/`Secure`/`SameSite`.
- Emit `CASA3-AUT-06` findings into `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

# SDD Iteration 044 Spec: AUT-01 Deep Automation

## Control Under Audit
- **ID:** `AUT-01`
- **Requirement:** No default, shared or vendor-supplied credentials accepted (`OWASP ASVS V2.5.4 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only replayed a single credential pair (`admin@juice-sh.op` / `admin123`) against one hardcoded endpoint.
2. Lacked a combined generic + product-derived default credential corpus and login surface discovery with SPA fallback filtering.
3. Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`) were not redacted in `output/dast-capture.har`, and `CASA3-AUT-01` SARIF 2.1.0 entries were missing.

## Requirements
- Redact sensitive auth headers in `http_probe` before recording into `output/dast-capture.har`.
- Discover active login endpoints (`/rest/user/login`, `/api/login`, `/auth/login`) avoiding SPA HTML false positives and replay a combined generic + product-derived default credential corpus (12 pairs).
- Fail whenever `>= 1` credential pair authenticates, emitting masked `CASA3-AUT-01` findings to `output/dast-findings.sarif`.

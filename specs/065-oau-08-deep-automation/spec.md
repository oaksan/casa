# Specification — SDD 065: OAU-08 Deep Automation

- **Control ID:** `OAU-08`
- **Title:** Access tokens are transmitted only in the `Authorization` header; never in query strings or URL fragments
- **External References:** RFC 6750 §2.3; ASVS V3.1.1 (L1)
- **Applicable Profile:** `All`

## Requirements
1. Preserve the authentication scheme in redacted HAR 1.2 headers (`Bearer [REDACTED]` / `DPoP [REDACTED]`) while keeping token values redacted.
2. Scan the full HAR 1.2 proxy capture (`har_entries`) verifying `Authorization: Bearer|DPoP` usage and detecting query/fragment JWT or `access_token`/`id_token` leaks on resource endpoints (excluding `/token`, `/revoke`, `/introspect`).
3. Actively probe protected backend resource endpoints with `?access_token=` and `?token=` query parameters.
4. Inspect live served JS bundles (`main.js`), `user.service.ts`, and `app.routing.ts` for resource query-string `access_token=` transmission and `#access_token=` URL fragment transport, emitting `CASA3-OAU-08` to `output/dast-findings.sarif`.

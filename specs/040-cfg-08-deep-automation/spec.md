# SDD Iteration 040 Spec: CFG-08 Deep Automation

## Control Under Audit
- **ID:** `CFG-08`
- **Requirement:** CORS uses a strict allow list; no wildcard with credentials; no unvalidated origin reflection (`OWASP ASVS V14.5.3 (L1); CWE-942`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only sent 1 probe (`GET /rest/products/search?q=apple`, `Origin: https://evil.example.com`).
2. Did not test `Origin: null`, domain-suffix-sharing origin (`https://not<host>`), `OPTIONS` preflight, authenticated endpoints, or `Access-Control-Allow-Credentials: true` combined with `*`.
3. Missing `CASA3-CFG-08` entries in `output/dast-findings.sarif`.

## Requirements
- Probe 7 public, authenticated/sensitive, and `OPTIONS` preflight endpoints across 3 attack origins (`https://evil.example.com`, `null`, `https://not<host>`).
- Flag unvalidated origin reflection, `null` origin acceptance, `*` + `Allow-Credentials: true`, and wildcard `*` without a strict allowlist on authenticated/sensitive endpoints.
- Emit `CASA3-CFG-08` findings to `output/dast-findings.sarif` alongside `output/dast-capture.har`.

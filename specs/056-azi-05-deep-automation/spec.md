# SDD Iteration 056 Spec: AZI-05 Deep Automation

## Control Under Audit
- **ID:** `AZI-05`
- **Requirement:** No Local/Remote File Inclusion or path traversal (`OWASP ASVS V5.3.9, V12.3.2, V12.3.3 (L1); CWE-22, CWE-98`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner sent only 1 fixed probe (`/ftp/package.json.bak%2500.md`) without testing encoded, double-encoded, absolute, or UNC traversal variants or remote file inclusion endpoints (`POST /profile/image/url`).
2. Missing `CASA3-AZI-05` SARIF 2.1.0 entries and redacted HAR 1.2 artifact links.

## Requirements
- Probe all 5 required payload forms (encoded `..%2f`, double-encoded `..%252f`, null-byte `%2500.md`, absolute `%2fetc%2fpasswd`, UNC `%5c%5c...`) across `/ftp/` and `/support/logs/`.
- Test authenticated Remote File Inclusion (`POST /profile/image/url`) backed by an ephemeral HTTP listener (`RfiCallbackHandler`).
- Emit `CASA3-AZI-05` findings to `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

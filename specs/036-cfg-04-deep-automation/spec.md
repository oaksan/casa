# SDD Iteration 036 Spec: CFG-04 Deep Automation

## Control Under Audit
- **ID:** `CFG-04`
- **Requirement:** Content-Security-Policy enforced; `script-src` excludes `unsafe-inline` and `unsafe-eval` (`OWASP ASVS V14.4.3 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only evaluated `root_headers` (`/`), ignoring all secondary HTML routes discovered during crawling.
2. No directive parser existed to resolve `script-src` -> `default-src` fallback precedence or detect forbidden `*` and `data:` tokens and `Report-Only`-only deployments.
3. Missing `CASA3-CFG-04` entries in `output/dast-findings.sarif`.

## Requirements
- Inspect every HTML route captured in `crawled_exchanges`.
- Parse CSP directives, resolve effective `script-src` (`script-src` or `default-src` fallback), and fail on missing CSP or forbidden tokens (`unsafe-inline`, `unsafe-eval`, `*`, `data:`).
- Emit `CASA3-CFG-04` findings into `output/dast-findings.sarif` alongside `output/dast-capture.har`.

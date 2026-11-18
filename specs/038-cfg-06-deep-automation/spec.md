# SDD Iteration 038 Spec: CFG-06 Deep Automation

## Control Under Audit
- **ID:** `CFG-06`
- **Requirement:** `X-Content-Type-Options: nosniff` on all responses (`OWASP ASVS V14.4.4 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only checked `root_headers` (`GET /`), producing a false `PASS` when `/metrics` omitted `X-Content-Type-Options`.
2. Did not compute 100% response compliance across `crawled_exchanges` + representative static assets.
3. Missing `CASA3-CFG-06` entries in `output/dast-findings.sarif`.

## Requirements
- Probe static asset `/ftp/legal.md` and evaluate every unique valid HTTP response (`status > 0`) in `crawled_exchanges`.
- Require `X-Content-Type-Options: nosniff` on 100% of responses (fail on `< 100%`).
- Emit `CASA3-CFG-06` findings into `output/dast-findings.sarif` alongside `output/dast-capture.har`.

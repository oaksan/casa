# SDD Iteration 041 Spec: CFG-09 Deep Automation

## Control Under Audit
- **ID:** `CFG-09`
- **Requirement:** 4xx/5xx responses return generic messages; no stack traces, internal paths or routing detail (`OWASP ASVS V7.4.1 (L1); CWE-209`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only probed `/rest/products/search?q=%27))` and checked SQLite-specific strings.
2. Missing malformed type probes, oversize body (`413`) probes, `404 ENOENT` path leak probes, `401` stacktrace checks, and crawl-wide `4xx`/`5xx` inspection.
3. Missing `CASA3-CFG-09` SARIF 2.1.0 entries in `output/dast-findings.sarif`.

## Requirements
- Send 6 forced-error probes (SQL syntax, eval error, 404 missing file, 401 unauthorized type probe, malformed schema payload, 200 KB oversize JSON payload).
- Inspect every `4xx`/`5xx` response across `crawled_exchanges` for `stack_frame`, `filesystem_path`, `sql_fragment`, and `internal_routing_or_module`.
- Emit `CASA3-CFG-09` findings into `output/dast-findings.sarif` alongside `output/dast-capture.har`.

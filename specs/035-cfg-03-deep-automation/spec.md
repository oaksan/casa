# SDD Iteration 035 Spec: CFG-03 Deep Automation

## Control Under Audit
- **ID:** `CFG-03`
- **Requirement:** No detailed version or stack disclosure in headers or response bodies (`OWASP ASVS V14.3.3 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only checked `Server`/`X-Powered-By` on `/` and `nodejs_version_info` in `/metrics`, instead of inspecting all response headers and bodies across the crawl.
2. Missing normative product version token check `[A-Za-z-]+/[0-9]+\.[0-9]+`, `/rest/admin/application-version`, `<meta name="generator">`, stack headers, and dependency stack traces.
3. Missing `CASA3-CFG-03` SARIF 2.1.0 entries in `output/dast-findings.sarif`.

## Requirements
- Capture every `http_probe` exchange in `crawled_exchanges` (`method`, `url`, `status`, `headers`, `body`).
- Inspect all crawled headers and bodies for `[A-Za-z-]+/[0-9]+\.[0-9]+` tokens, stack-disclosure headers, runtime version metrics, unauthenticated version JSON endpoints, meta generators, and traceback dependency leaks.
- Emit `CASA3-CFG-03` findings to `output/dast-findings.sarif` alongside `output/dast-capture.har`.

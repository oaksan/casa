# SDD Iteration 034 Spec: CFG-02 Deep Automation

## Control Under Audit
- **ID:** `CFG-02`
- **Requirement:** Framework and server debug modes disabled in production (`OWASP ASVS V14.3.2 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only probed `/metrics`, missing `/api-docs/`, `/rest/admin/application-configuration`, and 16 common framework debug/profiler/actuator endpoints.
2. No active error-triggering probes existed to detect framework traceback pages (Express `errorhandler`, Werkzeug, Django, Rails, ASP.NET).
3. Missing SPA catch-all response filtering and `CASA3-CFG-02` emission into `output/dast-findings.sarif`.

## Requirements
- Probe 19 known framework debug/profiler/actuator endpoints with SPA catch-all suppression (`<app-root>` guard) and payload signature verification.
- Execute active error probes (malformed JSON body + malformed query) matching framework traceback signatures.
- Emit `CASA3-CFG-02` findings into `output/dast-findings.sarif` and record HTTP exchanges in `output/dast-capture.har`.

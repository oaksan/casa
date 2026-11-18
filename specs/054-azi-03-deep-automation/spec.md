# SDD Iteration 054 Spec: AZI-03 Deep Automation

## Control Under Audit
- **ID:** `AZI-03`
- **Requirement:** No SQL or NoSQL injection (`OWASP ASVS V5.3.4 (L1); CWE-89, CWE-943`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only sent 1 SQLi payload (`POST /rest/user/login`) without differential result-set comparison or NoSQL (`$where`, `$ne`, `$regex`) injection probes.
2. Missing `CASA3-AZI-03` SARIF 2.1.0 entries and redacted HAR 1.2 links.

## Requirements
- Execute 8 active SQLi + NoSQLi differential probes across login, product search (`q=`), and order tracking (`MarsDB $where`).
- Confirm authentication bypass, boolean result-set growth (0 -> 28 captured records), uncaught SQLite syntax error, and MarsDB `$where` result-set growth (1 -> 3 order records), plus JSON `$ne`/`$regex` operator probes.
- Emit `CASA3-AZI-03` findings to `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

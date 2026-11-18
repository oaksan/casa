# SDD Iteration 033 Spec: CFG-01 Deep Automation

## Control Under Audit
- **ID:** `CFG-01`
- **Requirement:** Directory browsing disabled; file and directory enumeration not possible (`OWASP ASVS V4.3.2 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only probed `/ftp`, missing `/encryptionkeys`, `/support/logs`, `/infrastructure`, `/.well-known`, and nested subdirectories.
2. Lacked a structured autoindex + S3 `ListBucketResult` parser with entry extraction.
3. No SARIF 2.1.0 DAST artifact (`output/dast-findings.sarif`) was generated alongside `output/dast-capture.har`.

## Requirements
- Crawl `/` HTML links, `robots.txt`, common sensitive directory prefixes, and recursively enqueue subdirectories discovered in directory listings (up to a bounded cap).
- Parse Express `serveIndex`, web server autoindex HTML, and S3 `ListBucketResult` XML responses.
- Emit SARIF 2.1.0 (`output/dast-findings.sarif`) entries (`CASA3-CFG-01`) and W3C HAR 1.2 (`output/dast-capture.har`).

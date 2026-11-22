# SDD 095 — CFG-01: Guide-Compliant Reference Tooling (`OWASP ZAP 2.17.0`)

## Objective
Align control **CFG-01** (`Directory browsing disabled; file and directory enumeration not possible`) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 4 reference tooling (**OWASP ZAP**), executing real `zap.sh` Automation Framework (`spider`, `requestor`, `passiveScan-wait`, `traditional-json` & `sarif-json` reports) combined with S3 `ListBucketResult` XML and nested autoindex recursion.

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `CFG-01` — ASVS V4.3.2 (L1) (`Web_Application`)
- **Evidence:** DAST findings in SARIF 2.1.0 (`output/dast-findings.sarif`, `output/zap-findings.sarif`) + HAR 1.2 (`output/dast-capture.har`) + ZAP JSON (`output/zap-report.json`).
- **Test Procedure:** Spider every declared web origin with OWASP ZAP, request discovered/common directory prefixes, and inspect responses for directory listings.
- **Verification:**
  - **PASS:** Zero responses report ZAP Directory Browsing (`pluginid 10033 / 0`) or parse as HTML autoindex / S3 `ListBucketResult`.
  - **FAIL:** `>= 1` directory index detected by ZAP or autoindex / `ListBucketResult` parser.

## Acceptance Criteria
1. Install official OWASP ZAP `2.17.0` (`/home/user/.local/share/zaproxy`, `/home/user/.local/bin/zap.sh`) and define `ZAP_BIN` + `run_zap_automation(...)` with isolated `-dir` and bounded timeout so runs never hang.
2. `evaluate_cfg01_directory_browsing(...)` runs ZAP spider + requestor + passive scan + SARIF/JSON export, merges ZAP `Directory Browsing` (`10033`/`0`) findings with `parse_directory_index_body` (HTML autoindex + Express `serveIndex` + S3 `ListBucketResult`), and deduplicates findings cleanly.
3. Unit tests (`test_iteration95_cfg01_guide_tooling`) verify with real ZAP `2.17.0`:
   - `PASS` on clean static web server,
   - `FAIL` on HTML `Index of /files` directory listing (caught by ZAP `10033` + parser),
   - `FAIL` on S3 `ListBucketResult` XML endpoint.
4. Live OWASP Juice Shop (`http://localhost:3000`) scan retains real ZAP JSON/SARIF artifacts and confirms `CFG-01 = FAIL`.

# SDD 097 — CFG-03: Guide-Compliant Reference Tooling (`OWASP ZAP 2.17.0 Rules 10036/10037 + Header/Body Crawler`)

## Objective
Align control **CFG-03** (`No detailed version or stack disclosure in headers or response bodies`) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 4 reference tooling (**OWASP ZAP**), integrating ZAP passive disclosure rules (`10036` Server Leaks Version Information, `10037` X-Powered-By Header Disclosure) with full-crawl header and body `[A-Za-z-]+/[0-9]+\.[0-9]+` token inspection.

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `CFG-03` — ASVS V14.3.3 (L1) (`Web_Application`)
- **Evidence:** DAST findings in SARIF 2.1.0 (`output/dast-findings.sarif`, `output/zap-findings.sarif`) + HAR 1.2 (`output/dast-capture.har`) + ZAP JSON (`output/zap-report.json`).
- **Test Procedure:** Inspect response headers and bodies across the OWASP ZAP crawl for server, framework, and version identifiers.
- **Verification:**
  - **PASS:** Zero headers or response bodies disclose a product version token matching `[A-Za-z-]+/[0-9]+\.[0-9]+`, stack banner header (`X-Powered-By`, etc.), or runtime/version disclosure flagged by OWASP ZAP or the crawler.
  - **FAIL:** `>= 1` version token or stack banner disclosed.

## Acceptance Criteria
1. `evaluate_cfg03_version_disclosure(...)` reuses `zap_domain4_report` (or invokes `run_zap_automation` standalone), parses ZAP rules `10036` and `10037`, and inspects every HTTP exchange for `[A-Za-z-]+/[0-9]+\.[0-9]+`, `X-Powered-By`/`X-AspNet-*`, `nodejs_version_info`, version JSON endpoints, `<meta name="generator">`, and framework stack traces.
2. Deduplicates findings cleanly and appends `CASA3-CFG-03` results to `output/dast-findings.sarif`.
3. Unit tests (`test_iteration97_cfg03_guide_tooling`) verify with real **OWASP ZAP 2.17.0**:
   - `PASS` on clean server (`Server: AppGateway` without version token),
   - `FAIL` on server disclosing `Server: nginx/1.24.0` + `X-Powered-By: Express` (flagged by ZAP rules `10036`/`10037`),
   - `FAIL` on response body product/runtime version token disclosure.
4. Live OWASP Juice Shop (`http://localhost:3000`) scan confirms `CFG-03 = FAIL` with ZAP SARIF/JSON + DAST SARIF evidence.

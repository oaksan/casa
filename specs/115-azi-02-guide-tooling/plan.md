# Implementation Plan 115 — AZI-02 (`OWASP ZAP 40012/40014` + `Headless Chrome OOB Callback`)

1. Extend `run_zap_automation(...)` in `casa-assessment/casa_audit/scanner.py` with optional `active_scan_rules: list[int] | None = None` so focused active XSS scans (`40012`, `40014` at `Low` strength/threshold with `defaultThreshold: Off`) execute cleanly in ~18s without impacting Domain 4 passive scans.
2. Extract `evaluate_azi02_xss(...)` in `casa-assessment/casa_audit/scanner.py` combining:
   - Authenticated/seeded OWASP ZAP active XSS scan (`40012`, `40014`) outputting `output/zap-xss-report.json` + `output/zap-xss-findings.sarif`;
   - Stored/reflected XSS seeding (`/api/Feedbacks/` captcha solve + `/profile` + HTML reflection check);
   - Ephemeral out-of-band HTTP callback server (`XssCallbackHandler`) + Headless Chrome CDP (`scripts/headless_xss_callback.js`) confirming live JS execution across DOM (`/#/search?q=`), Stored (`/#/about`, `/profile`), and Reflected (`/?q=` or configured) routes;
   - Frontend Angular `DomSanitizer.bypassSecurityTrustHtml()` sink check (excluding `.spec.ts`);
   - Evidence artifacts `output/azi02-xss-audit.json`, redacted `output/azi02-replayed.har`, and SARIF 2.1.0 (`CASA3-AZI-02`).
3. Wire `results["AZI-02"]` inside `run_dynamic_and_protocol_checks`.
4. Add `test_iteration115_azi02_guide_tooling` in `casa-assessment/tests/test_iteration1.py` exercising real OWASP ZAP `40012` AND real Headless Chrome OOB callback:
   - **PASS:** Properly HTML-escaped search endpoint -> `0` ZAP XSS alerts, `0` OOB callbacks, `[REDACTED]` HAR + JSON audit verified;
   - **FAIL:** Unescaped reflected HTML XSS page triggering **both** real OWASP ZAP active `40012` AND live Headless Chrome OOB HTTP callback (`out_of_band_http_callback`) -> `CASA3-AZI-02`.
5. Append `CONTROLE 45/61: AZI-02 (Iteração SDD 115)` to `docs/justificativa2.txt`.
6. Run full `unittest` suite (`48` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`) with refreshed `casa_audit` daemon, check off `tasks.md`, commit, tag `sdd-115`, and push `main` + tags.

# Implementation Plan — Iteration 053 (`AZI-02`)

1. Move `http.server` and `threading` imports to module top-level in `casa-assessment/casa_audit/scanner.py`.
2. Add `casa-assessment/scripts/headless_xss_callback.js` to drive `/usr/bin/google-chrome --headless=new` with CDP cookie injection across `/#/about`, `/#/search?q=...`, and `/profile`.
3. Update `AZI-02` to run `XssCallbackHandler` out-of-band HTTP callback verification alongside authenticated stored/reflected probes and `.spec.ts`-filtered `bypassSecurityTrustHtml` inventory.
4. Emit `CASA3-AZI-02` findings to `dast_sarif_results` (`output/dast-findings.sarif`).
5. Verify against OWASP Juice Shop (`http://localhost:3000`), update `docs/justificativa.txt` and `tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-053`, and push.

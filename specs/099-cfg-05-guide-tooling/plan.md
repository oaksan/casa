# Implementation Plan 099 — CFG-05 (`OWASP ZAP`)

1. Add `evaluate_cfg05_clickjacking(...)` in `casa-assessment/casa_audit/scanner.py` reusing `zap_domain4_report` (or executing `run_zap_automation(...)` autonomously), correlating OWASP ZAP Passive Rule `10020` (*Missing Anti-clickjacking Header*) with multi-route HTML inspection for `X-Frame-Options` (`DENY` / `SAMEORIGIN`) and CSP `frame-ancestors`.
2. Wire `results["CFG-05"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration99_cfg05_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering real OWASP ZAP `2.17.0` runs on `X-Frame-Options: SAMEORIGIN` (`PASS`), `CSP frame-ancestors 'none'` (`PASS`), unprotected HTML flagged by ZAP Rule `10020` (`FAIL`), and `frame-ancestors *` (`FAIL`).
4. Append `CONTROLE 29/61: CFG-05 (Iteração SDD 099)` to `docs/justificativa2.txt`.
5. Run the full `unittest` suite (`32` tests) to completion, then run a live scan against OWASP Juice Shop, commit, tag `sdd-099`, and push.

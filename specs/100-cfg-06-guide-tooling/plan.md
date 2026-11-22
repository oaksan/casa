# Implementation Plan 100 — CFG-06 (`OWASP ZAP`)

1. Add `evaluate_cfg06_xcto(...)` in `casa-assessment/casa_audit/scanner.py` reusing `zap_domain4_report` (or executing `run_zap_automation(...)` autonomously), correlating OWASP ZAP Passive Rule `10021` (*X-Content-Type-Options Header Missing*) with 100% crawl header verification (`x-content-type-options == "nosniff"`).
2. Wire `results["CFG-06"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration100_cfg06_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering 100% `nosniff` (`PASS`), missing on `/metrics` caught by real OWASP ZAP Rule `10021` (`FAIL`), and malformed value (`FAIL`).
4. Append `CONTROLE 30/61: CFG-06 (Iteração SDD 100)` to `docs/justificativa2.txt`.
5. Run the full `unittest` suite (`33` tests) to completion, execute the live OWASP Juice Shop scan, commit, tag `sdd-100`, and push.

# Plan 129 — WHK-01 Guide-Compliant Tooling

1. Add `CASA3-WHK-01-cleartext-webhook-url` rule in `casa-assessment/rules/casa3_al1_oauth.yml` (reused for Domain 7/8 custom rules, or scanned cleanly via `_run_oauth_semgrep_sarif`).
2. Add `evaluate_whk01_tls_enforcement` in `casa-assessment/casa_audit/scanner.py` preserving `evaluate_whk01_delivery_tls` 4-tuple compatibility, integrating `run_testssl_scan` (`testssl.sh` JSON) over HTTPS webhook receiver hosts, `_make_redacted_har_probe` for cleartext delivery probes, `output/whk01-tls-audit.json`, redacted `output/whk01-replayed.har`, `output/whk01-testssl.json`, and `CASA3-WHK-01` SARIF 2.1.0 entries.
3. Wire `evaluate_whk01_tls_enforcement` in `run_dynamic_and_protocol_checks` (`results["WHK-01"]`).
4. Add `test_iteration129_whk01_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering PASS (cleartext HTTP `301 -> https://` + HTTPS receiver running TLS 1.2/1.3 only verified by real `testssl.sh` JSON + redacted HAR), FAIL (cleartext HTTP `202` accepted + legacy TLS 1.0/1.1 + static `http://` webhook config), and `Not_Covered` (app with 0 webhook facilities).
5. Document in `docs/justificativa2.txt`, run isolated + full `unittest` suite, execute live Juice Shop scan, commit, tag `sdd-129`, and push.

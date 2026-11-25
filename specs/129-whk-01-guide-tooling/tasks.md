# Tasks 129 — WHK-01 Guide-Compliant Tooling

- [x] Add `CASA3-WHK-01-cleartext-webhook-url` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Add `evaluate_whk01_tls_enforcement` in `casa-assessment/casa_audit/scanner.py` (with `run_testssl_scan`, `_make_redacted_har_probe`, JSON + HAR) and wire `WHK-01` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration129_whk01_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 59/61: WHK-01 (Iteração SDD 129)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`62` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `WHK-01` + `output/whk01-tls-audit.json` + `output/whk01-replayed.har`.
- [x] Commit SDD 129 files, create annotated tag `sdd-129`, and push `main` + tags to `origin`.

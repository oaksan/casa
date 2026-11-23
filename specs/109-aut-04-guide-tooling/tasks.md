# Tasks 109 — AUT-04 Guide-Compliant Tooling

- [x] Enable ZAP passive rules `3`/`10024`/`10025` and capture `request_headers` in `crawled_exchanges`.
- [x] Extract `evaluate_aut04_url_token_leak` in `casa-assessment/casa_audit/scanner.py` and wire `AUT-04` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration109_aut04_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 39/61: AUT-04 (Iteração SDD 109)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`42` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AUT-04` + `output/aut04-replayed.har`.
- [x] Commit SDD 109 files, create annotated tag `sdd-109`, and push `main` + tags to `origin`.

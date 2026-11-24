# Tasks 122 — OAU-03 Guide-Compliant Tooling

- [x] Extract `evaluate_oau03_redirect_uris` in `casa-assessment/casa_audit/scanner.py` and wire `OAU-03` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration122_oau03_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 52/61: OAU-03 (Iteração SDD 122)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`55` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-03` + `output/oau03-redirect-audit.json` + `output/oau03-replayed.har`.
- [x] Commit SDD 122 files, create annotated tag `sdd-122`, and push `main` + tags to `origin`.

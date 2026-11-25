# Tasks 127 — OAU-08 Guide-Compliant Tooling

- [x] Add `CASA3-OAU-08-token-in-url-transport` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Extract `evaluate_oau08_token_transport` in `casa-assessment/casa_audit/scanner.py` and wire `OAU-08` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration127_oau08_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 57/61: OAU-08 (Iteração SDD 127)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`60` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-08` + `output/oau08-transport-audit.json` + `output/oau08-replayed.har`.
- [x] Commit SDD 127 files, create annotated tag `sdd-127`, and push `main` + tags to `origin`.

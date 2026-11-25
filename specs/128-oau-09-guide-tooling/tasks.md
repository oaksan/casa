# Tasks 128 — OAU-09 Guide-Compliant Tooling

- [x] Add `CASA3-OAU-09-jwt-validation-weakness` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Extract `evaluate_oau09_token_validation` in `casa-assessment/casa_audit/scanner.py` and wire `OAU-09` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration128_oau09_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 58/61: OAU-09 (Iteração SDD 128)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`61` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-09` + `output/oau09-token-audit.json` + `output/oau09-replayed.har`.
- [x] Commit SDD 128 files, create annotated tag `sdd-128`, and push `main` + tags to `origin`.

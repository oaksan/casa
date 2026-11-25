# Tasks 126 — OAU-07 Guide-Compliant Tooling

- [x] Add `CASA3-OAU-07-insecure-token-storage` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Extract `evaluate_oau07_token_storage` in `casa-assessment/casa_audit/scanner.py` and wire `OAU-07` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration126_oau07_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 56/61: OAU-07 (Iteração SDD 126)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`59` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-07` + `output/oau07-storage-audit.json` + `output/oau07-replayed.har`.
- [x] Commit SDD 126 files, create annotated tag `sdd-126`, and push `main` + tags to `origin`.

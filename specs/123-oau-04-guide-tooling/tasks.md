# Tasks 123 — OAU-04 Guide-Compliant Tooling

- [x] Add `CASA3-OAU-04-missing-state-or-weak-prng` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Extract `evaluate_oau04_state_nonce` in `casa-assessment/casa_audit/scanner.py` and wire `OAU-04` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration123_oau04_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 53/61: OAU-04 (Iteração SDD 123)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`56` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-04` + `output/oau04-entropy-audit.json` + `output/oau04-replayed.har`.
- [x] Commit SDD 123 files, create annotated tag `sdd-123`, and push `main` + tags to `origin`.

# Tasks 130 — WHK-02 Guide-Compliant Tooling

- [x] Add `CASA3-WHK-02-weak-hmac-or-timing` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Add `evaluate_whk02_signature_verification` in `casa-assessment/casa_audit/scanner.py` and wire `WHK-02` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration130_whk02_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 60/61: WHK-02 (Iteração SDD 130)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`63` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `WHK-02` + `output/whk02-hmac-audit.json` + `output/whk02-replayed.har`.
- [x] Commit SDD 130 files, create annotated tag `sdd-130`, and push `main` + tags to `origin`.

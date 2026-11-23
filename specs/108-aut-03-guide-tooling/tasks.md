# Tasks 108 — AUT-03 Guide-Compliant Tooling

- [x] Add `_extract_session_cookies` and `evaluate_aut03_session_fixation` in `casa-assessment/casa_audit/scanner.py` and wire `AUT-03` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration108_aut03_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 38/61: AUT-03 (Iteração SDD 108)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`41` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AUT-03` + `output/aut03-replayed.har`.
- [x] Commit SDD 108 files, create annotated tag `sdd-108`, and push `main` + tags to `origin`.

# Tasks 107 — AUT-02 Guide-Compliant Tooling

- [x] Add `estimate_sp800_90b_token_min_entropy` and `evaluate_aut02_token_entropy` in `casa-assessment/casa_audit/scanner.py` and wire `AUT-02` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration107_aut02_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 37/61: AUT-02 (Iteração SDD 107)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`40` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AUT-02` + `output/aut02-sp800-90b.json`.
- [x] Commit SDD 107 files, create annotated tag `sdd-107`, and push `main` + tags to `origin`.

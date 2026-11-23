# Tasks 106 — AUT-01 Guide-Compliant Tooling

- [x] Add SecLists default-credentials corpus `casa-assessment/rules/seclists_aut01_default_creds.txt` and `SECLISTS_AUT01_CREDS` constant.
- [x] Add `evaluate_aut01_default_credentials` to `casa-assessment/casa_audit/scanner.py` and wire `AUT-01` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration106_aut01_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 36/61: AUT-01 (Iteração SDD 106)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`39` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AUT-01` + redacted HAR.
- [x] Commit SDD 106 files, create annotated tag `sdd-106`, and push `main` + tags to `origin`.

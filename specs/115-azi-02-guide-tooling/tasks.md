# Tasks 115 — AZI-02 Guide-Compliant Tooling

- [x] Add optional `active_scan_rules` to `run_zap_automation` and extract `evaluate_azi02_xss` in `casa-assessment/casa_audit/scanner.py`; wire `AZI-02` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration115_azi02_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 45/61: AZI-02 (Iteração SDD 115)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`48` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AZI-02` + `output/azi02-xss-audit.json` + `output/azi02-replayed.har`.
- [x] Commit SDD 115 files, create annotated tag `sdd-115`, and push `main` + tags to `origin`.

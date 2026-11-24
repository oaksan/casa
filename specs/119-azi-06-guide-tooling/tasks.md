# Tasks 119 — AZI-06 Guide-Compliant Tooling

- [x] Add `follow_redirects` to `_make_redacted_har_probe` and extract `evaluate_azi06_open_redirect_hpp` in `casa-assessment/casa_audit/scanner.py`; wire `AZI-06` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration119_azi06_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 49/61: AZI-06 (Iteração SDD 119)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`52` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AZI-06` + `output/azi06-redirect-hpp-audit.json` + `output/azi06-replayed.har` + `output/zap-redirect-findings.sarif`.
- [x] Commit SDD 119 files, create annotated tag `sdd-119`, and push `main` + tags to `origin`.

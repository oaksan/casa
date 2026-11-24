# Tasks 117 — AZI-04 Guide-Compliant Tooling

- [x] Extract `evaluate_azi04_cmd_injection` in `casa-assessment/casa_audit/scanner.py`; wire `AZI-04` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration117_azi04_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 47/61: AZI-04 (Iteração SDD 117)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`50` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AZI-04` + `output/azi04-cmdi-audit.json` + `output/azi04-replayed.har` + `output/zap-cmdi-findings.sarif`.
- [x] Commit SDD 117 files, create annotated tag `sdd-117`, and push `main` + tags to `origin`.

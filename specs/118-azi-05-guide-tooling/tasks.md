# Tasks 118 — AZI-05 Guide-Compliant Tooling

- [x] Extract `evaluate_azi05_lfi_rfi` in `casa-assessment/casa_audit/scanner.py`; wire `AZI-05` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration118_azi05_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 48/61: AZI-05 (Iteração SDD 118)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`51` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AZI-05` + `output/azi05-lfi-rfi-audit.json` + `output/azi05-replayed.har` + `output/zap-lfi-findings.sarif`.
- [x] Commit SDD 118 files, create annotated tag `sdd-118`, and push `main` + tags to `origin`.

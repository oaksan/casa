# Tasks 114 — AZI-01 Guide-Compliant Tooling

- [x] Extract `_extract_csrf_token` and `evaluate_azi01_anti_csrf` in `casa-assessment/casa_audit/scanner.py` and wire `AZI-01` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration114_azi01_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 44/61: AZI-01 (Iteração SDD 114)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`47` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AZI-01` + `output/azi01-replayed.har`.
- [x] Commit SDD 114 files, create annotated tag `sdd-114`, and push `main` + tags to `origin`.

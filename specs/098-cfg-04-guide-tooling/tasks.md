# Tasks 098 — CFG-04 Guide-Compliant Tooling

- [x] Install official Google `csp_evaluator` (`1.1.8`) and add `NODE_BIN` + `CSP_EVALUATOR_PKG` constants in `casa-assessment/casa_audit/scanner.py`.
- [x] Add `run_csp_evaluator_batch` and `evaluate_cfg04_csp` in `casa-assessment/casa_audit/scanner.py` and wire `CFG-04` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration98_cfg04_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 28/61: CFG-04 (Iteração SDD 098)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`31` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `CFG-04` + `output/csp-evaluator.json`.
- [x] Commit SDD 098 files, create annotated tag `sdd-098`, and push `main` + tags to `origin`.

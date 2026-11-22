# Tasks 097 — CFG-03 Guide-Compliant Tooling

- [x] Add `evaluate_cfg03_version_disclosure` to `casa-assessment/casa_audit/scanner.py` and wire `CFG-03` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration97_cfg03_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering clean (`PASS`), `Server: nginx/1.24.0` + `X-Powered-By: Express` via real ZAP `10036`/`10037` (`FAIL`), and body version disclosure (`FAIL`).
- [x] Append `CONTROLE 27/61: CFG-03 (Iteração SDD 097)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`30` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `CFG-03` + artifacts.
- [x] Commit SDD 097 files, create annotated tag `sdd-097`, and push `main` + tags to `origin`.

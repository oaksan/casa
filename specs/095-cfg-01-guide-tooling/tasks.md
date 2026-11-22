# Tasks 095 — CFG-01 Guide-Compliant Tooling

- [x] Install official OWASP ZAP `2.17.0` (`/home/user/.local/share/zaproxy`, symlink `/home/user/.local/bin/zap.sh`) and benchmark Automation Framework (`22.4s`, `sarif-json` + `traditional-json`).
- [x] Add `ZAP_BIN`, `run_zap_automation`, `parse_directory_index_body`, and `evaluate_cfg01_directory_browsing` to `casa-assessment/casa_audit/scanner.py`, and wire `CFG-01` inside `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration95_cfg01_guide_tooling` in `casa-assessment/tests/test_iteration1.py` verifying real ZAP `2.17.0` (`PASS` clean, `FAIL` HTML autoindex, `FAIL` S3 `ListBucketResult`).
- [x] Document `CONTROLE 25/61: CFG-01 (Iteração SDD 095)` in `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`28` tests) to completion (`465.266s`, `OK`).
- [x] Start Juice Shop (`3000`) & `casa_audit` (`8080`) daemons and verify live `POST /api/scan` (`CFG-01 = FAIL`, `output/zap-report.json`, `output/zap-findings.sarif`).
- [ ] Commit SDD 095 files, create annotated tag `sdd-095`, and push `main` + tags to `origin`.

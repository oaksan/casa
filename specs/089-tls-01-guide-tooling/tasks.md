# Tasks 089 — TLS-01 Guide-Compliant Tooling

- [x] Install official `testssl.sh` (`3.2.2`) into `/home/user/.local/share/testssl.sh` with `/home/user/.local/bin/testssl.sh` symlink and benchmark JSON output (`-p --jsonfile-pretty`).
- [x] Add `TESTSSL_BIN`, `run_testssl_scan`, and `evaluate_tls01_transport_enforcement` to `casa-assessment/casa_audit/scanner.py` and integrate into `run_dynamic_and_protocol_checks` (`TLS-01` & `output/tls-scan.json`).
- [x] Add `test_iteration89_tls01_guide_tooling` to `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 19/61: TLS-01 (Iteração SDD 089)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`test_iteration1.py`) to completion (22 tests OK).
- [x] Start Juice Shop (`http://localhost:3000`) & `casa_audit` (`127.0.0.1:8080`) daemons and verify live `POST /api/scan` (`TLS-01 = FAIL`, `output/tls-scan.json`, `output/testssl-raw.json`).
- [ ] Commit SDD 089 artifacts, create annotated tag `sdd-089`, and push `main` + tags to `origin`.

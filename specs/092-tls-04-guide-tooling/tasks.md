# Tasks 092 — TLS-04 Guide-Compliant Tooling

- [x] Add `extra_args` support to `run_testssl_scan`, implement `parse_testssl_certificate` and `evaluate_tls04_certificate_validation` in `casa-assessment/casa_audit/scanner.py`, and wire `TLS-04` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration92_tls04_guide_tooling` in `casa-assessment/tests/test_iteration1.py` validating trusted CA (`PASS`), `< 30 days` informational (`PASS`), self-signed (`FAIL`), hostname mismatch (`FAIL`), and cleartext HTTP (`FAIL`) with real `testssl.sh 3.2.2`.
- [x] Append `CONTROLE 22/61: TLS-04 (Iteração SDD 092)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`25` tests) to completion (`OK`).
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `TLS-04` + `output/tls-scan.json`.
- [ ] Commit SDD 092 files, create annotated tag `sdd-092`, and push `main` + tags to `origin`.

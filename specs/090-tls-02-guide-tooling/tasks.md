# Tasks 090 — TLS-02 Guide-Compliant Tooling

- [x] Add `parse_testssl_protocols` and `evaluate_tls02_protocol_enforcement` to `casa-assessment/casa_audit/scanner.py` and wire `TLS-02` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration90_tls02_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering modern TLS (`PASS`), legacy TLS 1.0/1.1 (`FAIL`), and cleartext HTTP (`FAIL`) with real `testssl.sh 3.2.2`.
- [x] Document `CONTROLE 20/61: TLS-02 (Iteração SDD 090)` in `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`23` tests) to completion (`OK`).
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `TLS-02` + `output/tls-scan.json`.
- [ ] Commit SDD 090 files, create annotated tag `sdd-090`, and push `main` + tags to `origin`.

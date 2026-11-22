# Tasks 091 — TLS-03 Guide-Compliant Tooling

- [x] Add `parse_testssl_ciphers` and `evaluate_tls03_cipher_enforcement` to `casa-assessment/casa_audit/scanner.py` and wire `TLS-03` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration91_tls03_guide_tooling` in `casa-assessment/tests/test_iteration1.py` validating hardened AEAD FS (`PASS`), static-RSA non-FS (`FAIL`), legacy CBC-SHA1 (`FAIL`), and cleartext HTTP (`FAIL`) via real `testssl.sh 3.2.2`.
- [x] Append `CONTROLE 21/61: TLS-03 (Iteração SDD 091)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`24` tests) to completion (`OK`).
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `TLS-03` + `output/tls-scan.json`.
- [ ] Commit SDD 091 files, create annotated tag `sdd-091`, and push `main` + tags to `origin`.

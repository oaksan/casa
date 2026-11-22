# Tasks 093 — TLS-05 Guide-Compliant Tooling

- [x] Add `parse_testssl_hsts` and `evaluate_tls05_hsts_enforcement` to `casa-assessment/casa_audit/scanner.py` and wire `TLS-05` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration93_tls05_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering `max-age=31536000` (`PASS`), `max-age=600` (`FAIL`), missing header (`FAIL`), and cleartext HTTP (`FAIL`) with real `testssl.sh 3.2.2`.
- [x] Append `CONTROLE 23/61: TLS-05 (Iteração SDD 093)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`26` tests) to completion (`OK`).
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `TLS-05` + `output/tls-scan.json`.
- [ ] Commit SDD 093 files, create annotated tag `sdd-093`, and push `main` + tags to `origin`.

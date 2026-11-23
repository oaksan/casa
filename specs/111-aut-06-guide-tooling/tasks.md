# Tasks 111 — AUT-06 Guide-Compliant Tooling

- [x] Enable ZAP passive rules `10010`/`10011`/`10054` in `run_zap_automation` and preserve multi-`Set-Cookie` headers in `http_probe`.
- [x] Extract `evaluate_aut06_session_cookie_flags` in `casa-assessment/casa_audit/scanner.py` and wire `AUT-06` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration111_aut06_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 41/61: AUT-06 (Iteração SDD 111)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`44` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AUT-06` + `output/aut06-replayed.har`.
- [x] Commit SDD 111 files, create annotated tag `sdd-111`, and push `main` + tags to `origin`.

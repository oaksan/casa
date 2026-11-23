# Tasks 112 — AUT-07 Guide-Compliant Tooling

- [x] Extract `evaluate_aut07_jwt_security` in `casa-assessment/casa_audit/scanner.py` and wire `AUT-07` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration112_aut07_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 42/61: AUT-07 (Iteração SDD 112)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`45` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AUT-07` + `output/aut07-jwt-audit.json` + `output/aut07-replayed.har`.
- [x] Commit SDD 112 files, create annotated tag `sdd-112`, and push `main` + tags to `origin`.

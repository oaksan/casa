# Tasks 116 — AZI-03 Guide-Compliant Tooling

- [x] Add `SQLMAP_BIN`, `run_sqlmap_scan`, and `evaluate_azi03_sqli_nosql` in `casa-assessment/casa_audit/scanner.py`; wire `AZI-03` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration116_azi03_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 46/61: AZI-03 (Iteração SDD 116)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`49` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AZI-03` + `output/azi03-sqli-nosql-audit.json` + `output/azi03-replayed.har` + `output/zap-sqli-findings.sarif`.
- [x] Commit SDD 116 files, create annotated tag `sdd-116`, and push `main` + tags to `origin`.

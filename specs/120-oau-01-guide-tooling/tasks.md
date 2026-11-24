# Tasks 120 — OAU-01 Guide-Compliant Tooling

- [x] Add `casa-assessment/rules/casa3_al1_oauth.yml` and validate with `semgrep --validate`.
- [x] Extract `evaluate_oau01_grant_type` in `casa-assessment/casa_audit/scanner.py` and wire `OAU-01` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration120_oau01_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 50/61: OAU-01 (Iteração SDD 120)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`53` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-01` + `output/oau01-grant-audit.json` + `output/oau01-replayed.har` + `output/oau01-semgrep.sarif`.
- [x] Commit SDD 120 files, create annotated tag `sdd-120`, and push `main` + tags to `origin`.

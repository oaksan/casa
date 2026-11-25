# Tasks 131 — WHK-03 Guide-Compliant Tooling

- [x] Add `CASA3-WHK-03-hardcoded-signing-secret` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Add `evaluate_whk03_ssrf_protection` in `casa-assessment/casa_audit/scanner.py` (with `interactsh`-style OOB listener, `_make_redacted_har_probe`, `gitleaks`, and Semgrep) and wire `WHK-03` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration131_whk03_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 61/61: WHK-03 (Iteração SDD 131)` + milestone closure block to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`64` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `WHK-03` + `output/whk03-ssrf-audit.json` + `output/whk03-replayed.har` + full 61-control summary.
- [x] Commit SDD 131 files, create annotated tag `sdd-131`, and push `main` + tags to `origin`.

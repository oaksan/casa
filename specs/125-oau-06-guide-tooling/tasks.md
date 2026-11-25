# Tasks 125 — OAU-06 Guide-Compliant Tooling

- [x] Add `CASA3-OAU-06-embedded-client-secret` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Upgrade `OAU-06` with ZIP/`strings` extraction + Semgrep + redacted token probes + `evaluate_oau06_client_secrets` in `casa-assessment/casa_audit/scanner.py`.
- [x] Add `test_iteration125_oau06_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 55/61: OAU-06 (Iteração SDD 125)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`58` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-06` + `output/oau06-secret-audit.json` + `output/oau06-replayed.har`.
- [x] Commit SDD 125 files, create annotated tag `sdd-125`, and push `main` + tags to `origin`.

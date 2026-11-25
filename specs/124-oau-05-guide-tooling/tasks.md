# Tasks 124 — OAU-05 Guide-Compliant Tooling

- [x] Add `CASA3-OAU-05-embedded-webview-oauth` to `casa-assessment/rules/casa3_al1_oauth.yml`.
- [x] Upgrade `OAU-05` with ZIP/APK/IPA extraction + Semgrep + intercepting proxy + `evaluate_oau05_system_browser` in `casa-assessment/casa_audit/scanner.py`.
- [x] Add `test_iteration124_oau05_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 54/61: OAU-05 (Iteração SDD 124)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`57` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-05` + `output/oau05-browser-audit.json` + `output/oau05-replayed.har`.
- [x] Commit SDD 124 files, create annotated tag `sdd-124`, and push `main` + tags to `origin`.

# Tasks 121 — OAU-02 Guide-Compliant Tooling

- [x] Add `CASA3-OAU-02-*` rule to `casa-assessment/rules/casa3_al1_oauth.yml` and validate with `semgrep --validate`.
- [x] Extract shared `_run_oauth_intercepting_proxy` helper, filter Semgrep by `control_id` in `OAU-01`, implement `evaluate_oau02_pkce`, and wire `OAU-02` in `casa-assessment/casa_audit/scanner.py`.
- [x] Add `test_iteration121_oau02_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 51/61: OAU-02 (Iteração SDD 121)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`54` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `OAU-02` + `output/oau02-pkce-audit.json` + `output/oau02-replayed.har` + `output/oau02-semgrep.sarif`.
- [x] Commit SDD 121 files, create annotated tag `sdd-121`, and push `main` + tags to `origin`.

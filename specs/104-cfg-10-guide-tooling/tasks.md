# Tasks 104 — CFG-10 Guide-Compliant Tooling

- [x] Add SecLists admin wordlist `casa-assessment/rules/seclists_cfg10_admin.txt` and `SECLISTS_CFG10_WORDLIST` constant.
- [x] Add `evaluate_cfg10_admin_reachability` to `casa-assessment/casa_audit/scanner.py` and wire `CFG-10` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration104_cfg10_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 34/61: CFG-10 (Iteração SDD 104)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`37` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `CFG-10`.
- [x] Commit SDD 104 files, create annotated tag `sdd-104`, and push `main` + tags to `origin`.

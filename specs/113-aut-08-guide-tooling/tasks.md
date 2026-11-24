# Tasks 113 — AUT-08 Guide-Compliant Tooling

- [x] Upgrade `casa-assessment/scripts/headless_storage_dump.js` to dump IndexedDB object stores and generic login/logout flows.
- [x] Extract `evaluate_aut08_client_storage` in `casa-assessment/casa_audit/scanner.py` and wire `AUT-08` in `run_dynamic_and_protocol_checks`.
- [x] Add `test_iteration113_aut08_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 43/61: AUT-08 (Iteração SDD 113)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`46` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `AUT-08` + `output/aut08-storage-dump.json` + `output/aut08-replayed.har`.
- [x] Commit SDD 113 files, create annotated tag `sdd-113`, and push `main` + tags to `origin`.

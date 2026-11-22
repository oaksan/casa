# Tasks 105 — CFG-11 Guide-Compliant Tooling

- [x] Install official ProjectDiscovery `dnsx` (`v1.3.1`) and add Nuclei takeover template `casa-assessment/rules/nuclei_cfg11/takeover-fingerprints.yaml`.
- [x] Add `DNSX_BIN`, `NUCLEI_CFG11_DIR`, `run_dnsx_resolve`, and `evaluate_cfg11_dns_takeover` in `casa-assessment/casa_audit/scanner.py` and wire `CFG-11`.
- [x] Add `test_iteration105_cfg11_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Append `CONTROLE 35/61: CFG-11 (Iteração SDD 105)` to `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`38` tests) to completion.
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `CFG-11` + Domain 4 completion.
- [x] Commit SDD 105 files, create annotated tag `sdd-105`, and push `main` + tags to `origin`.

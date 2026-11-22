# Tasks 096 — CFG-02 Guide-Compliant Tooling

- [x] Install ProjectDiscovery `nuclei v3.11.1` into `/home/user/.local/bin/nuclei`.
- [x] Author and validate 6 Nuclei YAML templates under `casa-assessment/rules/nuclei_cfg02/` (`4` Juice Shop findings verified in ~4s, 0 SPA false positives).
- [x] Add `NUCLEI_BIN`, `NUCLEI_CFG02_DIR`, `run_nuclei_scan`, and `evaluate_cfg02_debug_modes` to `casa-assessment/casa_audit/scanner.py` and wire `CFG-02` cleanly while preserving `is_spa_shell` / `is_spa_fallback`.
- [x] Add `test_iteration96_cfg02_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
- [x] Document `CONTROLE 26/61: CFG-02 (Iteração SDD 096)` in `docs/justificativa2.txt`.
- [x] Run full `unittest` suite (`29` tests) to completion (`OK`).
- [x] Run live OWASP Juice Shop scan (`POST /api/scan`) and inspect `CFG-02`, `output/nuclei-cfg02.sarif`, and `output/nuclei-cfg02.jsonl`.
- [ ] Commit SDD 096 files, create annotated tag `sdd-096`, and push `main` + tags to `origin`.

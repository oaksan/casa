# Plan 096 — CFG-02 (`Nuclei 3.11.1` + `OWASP ZAP 2.17.0` Debug Audit)

## Architecture
1. **Nuclei Engine & Rule Suite:**
   - Binary `/home/user/.local/bin/nuclei` (`v3.11.1`) registered via `NUCLEI_BIN` and `NUCLEI_CFG02_DIR` (`casa-assessment/rules/nuclei_cfg02`).
   - 6 single-template `.yaml` files validated via `nuclei -validate` covering all 19 framework debug endpoints and 6 traceback signatures with negative `<app-root` matching.
2. **`run_nuclei_scan` & `evaluate_cfg02_debug_modes` (`casa_audit/scanner.py`):**
   - Reusable `run_nuclei_scan` executes `nuclei -u <url> -t <rules> -duc -nc -silent -jle <jsonl> -se <sarif>` and parses JSONL findings.
   - `evaluate_cfg02_debug_modes` deduplicates Nuclei findings with matching `zap_domain4_report` debug/error alerts (`10023`, `90022`, `40042`) and emits `CASA3-CFG-02` SARIF results.
   - Preserves `is_spa_shell` and `is_spa_fallback` in `run_dynamic_and_protocol_checks` for downstream controls.
3. **Verification & Documentation:**
   - Add `test_iteration96_cfg02_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
   - Append `CONTROLE 26/61: CFG-02 (Iteração SDD 096)` to `docs/justificativa2.txt`.
   - Run full `unittest` suite (`29` tests), then run live Juice Shop scan (`POST /api/scan`), commit, tag `sdd-096`, and push.

# Plan 097 — CFG-03 (`OWASP ZAP 2.17.0` + Version/Stack Disclosure Analyzer)

## Architecture
1. **`evaluate_cfg03_version_disclosure(...)` (`casa_audit/scanner.py`):**
   - Reuses `zap_report` (`zap_domain4_report`) from `CFG-01` inside `run_dynamic_and_protocol_checks` (avoiding redundant JVM startups) or invokes `run_zap_automation` when run standalone.
   - Extracts ZAP alerts matching `pluginid in {"10036", "10037"}` (or `"leaks version"` / `"x-powered-by"`).
   - Evaluates `crawled_exchanges` (headers + URL-stripped response bodies against `[A-Za-z-]+/[0-9]+\.[0-9]+(?:\.[0-9]+)?`, stack headers, runtime Prometheus metrics, `/rest/admin/application-version` / `/version` JSON, `<meta name="generator">`, and `node_modules/` stack leaks).
2. **Evidence & Tool Attribution:**
   - Emits `CASA3-CFG-03` SARIF 2.1.0 entries and updates `results["CFG-03"]["tool"]` to cite `OWASP ZAP <ver> (Rules 10036/10037)`.
3. **Verification & Documentation:**
   - Add `test_iteration97_cfg03_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
   - Document `CONTROLE 27/61: CFG-03 (Iteração SDD 097)` in `docs/justificativa2.txt`.
   - Run full `unittest` suite (`30` tests), then run live Juice Shop scan (`POST /api/scan`), commit, tag `sdd-097`, and push.

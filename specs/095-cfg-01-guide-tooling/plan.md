# Plan 095 — CFG-01 (`OWASP ZAP 2.17.0` Spider + Directory Browsing)

## Architecture
1. **`ZAP_BIN` & `run_zap_automation(...)` (`casa_audit/scanner.py`):**
   - Resolves `/home/user/.local/bin/zap.sh` (`2.17.0`).
   - Executes `zap.sh -cmd -dir <isolated_temp_dir> -silent -autorun plan.yaml` with `stdin=subprocess.DEVNULL` and configurable timeout (never colliding on `~/.ZAP/.homelock`).
   - Generates `traditional-json` and `sarif-json` reports.
2. **`evaluate_cfg01_directory_browsing(...)`:**
   - Runs `run_zap_automation` seeded with discovered prefixes (`/`, `/robots.txt`, `/ftp`, `/encryptionkeys`, `/support/logs`, `/infrastructure`, `/.well-known`, etc.).
   - Parses ZAP plugin `10033`/`0` (`Directory Browsing`) alerts and complements them with nested `serveIndex` recursion & S3 `ListBucketResult` XML parsing via `parse_directory_index_body`.
3. **Output & Reuse:**
   - Exposes `zap_report` inside `run_dynamic_and_protocol_checks` so subsequent Domain 4 controls (`CFG-02`, `CFG-03`, `CFG-05`, `CFG-06`...) can reuse the single Domain 4 ZAP crawl without spawning JVM repeatedly!
4. **Verification & Documentation:**
   - Add `test_iteration95_cfg01_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
   - Document `CONTROLE 25/61: CFG-01 (Iteração SDD 095)` in `docs/justificativa2.txt`.
   - Execute full `unittest` suite (`28` tests) cleanly and run live Juice Shop scan (`POST /api/scan`).

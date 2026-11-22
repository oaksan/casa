# Plan 093 — TLS-05 (`testssl.sh --ssl-native -h` HSTS Inspection)

## Architecture
1. **`parse_testssl_hsts(scan_result)` (`casa_audit/scanner.py`):**
   - Inspects `headerResponse` entries in `scanResult` for `HSTS_time` (parsing `=(\d+)\s*seconds`), `HSTS` (`not offered`), `HSTS_subdomains`, and `HSTS_preload`.
2. **`evaluate_tls05_hsts_enforcement(target_url, raw_json_path=..., http_probe_fn=..., endpoints=..., testssl_info=...)`:**
   - Runs `run_testssl_scan(host, port, raw_json_path=..., checks=("--ssl-native", "-h"))` on HTTPS/TLS hosts and cross-checks `/`, `/api/Products`, and `/rest/admin/application-configuration` over HTTPS.
   - Computes minimum observed `HSTS_time` combining `testssl.sh` and multi-endpoint probes so neither root nor API sub-routes can silently drop HSTS.
3. **Output & Metadata:**
   - Persists `HSTS_time`, `source`, `testsslVersion`, `testsslHsts`, `endpointsChecked`, and `violations` in `output/tls-scan.json` (`tls05Hsts`), and updates `results["TLS-05"]["tool"]` to cite `testssl.sh <version> -h`.
4. **Verification & Documentation:**
   - Add `test_iteration93_tls05_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
   - Document `CONTROLE 23/61: TLS-05 (Iteração SDD 093)` in `docs/justificativa2.txt`.
   - Execute full `unittest` suite (`26` tests) and live OWASP Juice Shop scan (`POST /api/scan`).

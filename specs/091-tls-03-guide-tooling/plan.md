# Plan 091 — TLS-03 (`testssl.sh --ssl-native -s -f`)

## Architecture
1. **`parse_testssl_ciphers(scan_result, target_port)` (`casa_audit/scanner.py`):**
   - Inspects `ciphers` section for banned classes: `cipherlist_NULL`, `cipherlist_aNULL`, `cipherlist_EXPORT`, `cipherlist_LOW`, `cipherlist_3DES_IDEA`, `cipherlist_OBSOLETED`.
   - Checks `cipherlist_STRONG_NOFS` to detect non-Forward-Secrecy TLS 1.2 suites (keeping `nonForwardSecrecyTls12Offered` populated for both `TLS-03` and `TLS-06` `ROBOT`).
   - Checks `fs` (`FS`, `FS_ciphers`, `FS_ECDHE_curves`) and `cipherlist_STRONG_FS` to populate `strongForwardSecrecyOffered`.
2. **`evaluate_tls03_cipher_enforcement(target_url, raw_json_path=..., testssl_info=...)`:**
   - Reuses pre-parsed `-s -f` `testssl_info` if supplied; otherwise checks `is_https or _quick_tls_capable(host, port)` before invoking `run_testssl_scan(host, port, raw_json_path=..., checks=("--ssl-native", "-s", "-f"))`.
3. **Output & Metadata:**
   - Populates `cipherSuites` and `tls03CipherEnforcement` in `output/tls-scan.json`, updates `results["TLS-03"]["tool"]` to reference `testssl.sh <version> -s -f`.
4. **Verification & Documentation:**
   - Add `test_iteration91_tls03_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
   - Document `CONTROLE 21/61: TLS-03 (Iteração SDD 091)` in `docs/justificativa2.txt`.
   - Execute full `unittest` suite (`24` tests) and live Juice Shop scan (`POST /api/scan`).

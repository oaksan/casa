# Plan 094 — TLS-06 (`testssl.sh -H -I -T -C` + Renegotiation/ROBOT)

## Architecture
1. **`parse_testssl_vulnerabilities(scan_result, target_port)` (`casa_audit/scanner.py`):**
   - Extracts every entry in `scanResult[0]["vulnerabilities"]` (`id`, `severity`, `finding`, `cwe`, `cve`).
   - Classifies `HIGH`/`CRITICAL` into `highOrCriticalFindings` (`FAIL`) and lower non-`OK`/`INFO` severities into `informationalFindings` without failing.
2. **`evaluate_tls06_vulnerabilities(target_url, raw_json_path=..., testssl_info=..., cipher_audit=...)`:**
   - Uses `-H -I -T -C` (`timeout_sec=30`) — empirically benchmarked at ~13.5s cleanly — instead of blocking `-R`/`-BB` sockets.
   - Supplements `secure_renego` (`openssl s_client -connect` 4s timeout) and `ROBOT` (`cipher_audit["nonForwardSecrecyTls12Offered"]` or `kRSA:!ECDHE:!DHE` quick TLS 1.2 check) when absent from `testssl.sh` `scanResult`.
3. **Verification & Documentation:**
   - Run `test_iteration94_tls06_guide_tooling` + full `unittest` suite (`27` tests), watching timing carefully.
   - Restart Juice Shop (`3000`) & `casa_audit` (`8080`) daemons and verify live `POST /api/scan`.

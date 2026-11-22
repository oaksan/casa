# Plan 090 — TLS-02 (`testssl.sh -p` Protocol Matrix)

## Architecture
1. **`parse_testssl_protocols(scan_result)` (`casa_audit/scanner.py`):**
   - Maps `testssl.sh` JSON IDs `{"SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLS1": "TLS 1.0", "TLS1_1": "TLS 1.1", "TLS1_2": "TLS 1.2", "TLS1_3": "TLS 1.3"}`.
   - Marks `offered` iff `"offered"` in finding (case-insensitive) and `"not offered"` not in finding.
2. **`evaluate_tls02_protocol_enforcement(...)`:**
   - Reuses `testssl_info` when already executed on the same `(host, port)` (`is_https`), avoiding duplicate `testssl.sh` execution.
   - Otherwise checks if `(host, port)` accepts a TLS connection (or always invokes `run_testssl_scan` for HTTPS URLs) so official `testssl.sh -p` evaluates all 6 protocol versions without stalling against non-TLS plain-HTTP ports (`http://localhost:3000`).
3. **`tls-scan.json` & Tool Output:**
   - Records `tls02ProtocolEnforcement` with `probedPort`, `source`, `testsslVersion`, `modernOffered`, `deprecatedOffered`, and `verdict`.
   - Updates `results["TLS-02"]["tool"]` to cite official `testssl.sh` (`<version> -p Protocol Matrix`).
4. **Verification & Documentation:**
   - Add `test_iteration90_tls02_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
   - Append `CONTROLE 20/61: TLS-02 (Iteração SDD 090)` in `docs/justificativa2.txt`.
   - Execute full `unittest` suite (`23` tests) and live Juice Shop scan (`POST /api/scan`).

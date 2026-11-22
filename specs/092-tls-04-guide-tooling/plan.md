# Plan 092 — TLS-04 (`testssl.sh --ssl-native -S` X.509 Certificate Validation)

## Architecture
1. **`run_testssl_scan` Extension (`casa_audit/scanner.py`):**
   - Accept optional `extra_args: tuple[str, ...] = ()` appended before `--jsonfile-pretty`.
2. **`parse_testssl_certificate(scan_result, target_port)`:**
   - Extracts `cert_commonName`, `cert_subjectAltName`, `cert_trust`, `cert_chain_of_trust`, `cert_notBefore`, `cert_notAfter`, `cert_expirationStatus`, `cert_caIssuers`, `cert_signatureAlgorithm`, `cert_keySize` from `scanResult[0]["serverDefaults"]`.
   - Computes `chainTrustedToPublicRoot` from `cert_chain_of_trust` (`severity == "OK"` / `finding` starts with `"ok"`), `hostnameMatches` from `cert_trust` (`severity == "OK"` / `"ok via"`), and `notExpired` / `remainingDays` from `cert_notAfter` & `cert_expirationStatus`.
   - Marks `0 <= remainingDays < 30` as an **informational warning** (still `PASS` if chain & hostname succeed), and `remainingDays < 0` or `"expired"` in `cert_expirationStatus` as `FAIL`.
3. **`evaluate_tls04_certificate_validation(...)`:**
   - Checks `is_https or _quick_tls_capable(host, port)` before invoking `run_testssl_scan(..., checks=("--ssl-native", "-S"))`.
   - Preserves `.certificate` and `tls04CertificateValidation` schema in `output/tls-scan.json`, adding `source` and `testsslVersion`.
4. **Verification & Documentation:**
   - Add `test_iteration92_tls04_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
   - Append `CONTROLE 22/61: TLS-04 (Iteração SDD 092)` to `docs/justificativa2.txt`.
   - Execute full `unittest` suite (`25` tests) and live Juice Shop scan (`POST /api/scan`).

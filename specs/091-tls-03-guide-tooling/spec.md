# SDD 091 — TLS-03: Guide-Compliant Reference Tooling (`testssl.sh --ssl-native -s -f`)

## Objective
Align control **TLS-03** (`Only strong cipher suites; NULL, EXPORT, anonymous, RC4 and legacy CBC suites rejected; forward secrecy preferred`) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 3 reference tooling (`testssl.sh`), reading cipher suite categories (`ciphers`) and forward-secrecy inventory (`fs`) directly from `testssl.sh` JSON output.

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `TLS-03` — ASVS V9.1.2 (L1); NIST SP 800-52 Rev.2 (`Web_Application`)
- **Evidence:** Machine-readable (JSON) TLS scanner output for every declared host (`output/tls-scan.json`, `output/testssl-tls03-raw.json`).
- **Test Procedure:** Run `testssl.sh` (`--ssl-native -s -f`) against each declared host/TLS port and read cipher categories and forward secrecy status.
- **Verification:**
  - **PASS:** No `NULL`, `EXPORT`, anonymous (`aNULL`), `RC4` (`LOW`), `3DES`, or `OBSOLETED` (e.g., `CBC-SHA1`) suite is offered, `STRONG_NOFS` is not offered, and Forward Secrecy suites (`FS` / `STRONG_FS`) are offered.
  - **FAIL:** Any banned cipher category or non-FS TLS 1.2 suite (`cipherlist_STRONG_NOFS`) is offered, or zero strong Forward Secrecy cipher suites are offered.

## Acceptance Criteria
1. `parse_testssl_ciphers(scan_result)` parses `testssl.sh` `ciphers` (`cipherlist_NULL`, `cipherlist_aNULL`, `cipherlist_EXPORT`, `cipherlist_LOW`, `cipherlist_3DES_IDEA`, `cipherlist_OBSOLETED`, `cipherlist_STRONG_NOFS`, `cipherlist_STRONG_FS`) and `fs` (`FS`, `FS_ciphers`, `FS_ECDHE_curves`).
2. `evaluate_tls03_cipher_enforcement(...)` invokes `run_testssl_scan(..., checks=("--ssl-native", "-s", "-f"))` on HTTPS/TLS endpoints and returns `FAIL` quickly on cleartext HTTP endpoints without stalling.
3. Unit tests (`test_iteration91_tls03_guide_tooling`) verify with real `testssl.sh 3.2.2`:
   - `PASS` on hardened ECDHE AEAD TLS 1.2/1.3 server,
   - `FAIL` on static-RSA non-FS TLS 1.2 server (`cipherlist_STRONG_NOFS`),
   - `FAIL` on legacy CBC-SHA1 server (`cipherlist_OBSOLETED`),
   - `FAIL` on cleartext HTTP server.
4. Live OWASP Juice Shop (`http://localhost:3000`) scan confirms `TLS-03 = FAIL` cleanly.

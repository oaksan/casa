# SDD 092 — TLS-04: Guide-Compliant Reference Tooling (`testssl.sh --ssl-native -S`)

## Objective
Align control **TLS-04** (`Certificate chain is valid, trusted, unexpired and matches the hostname`) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 3 reference tooling (`testssl.sh`), extracting trust chain, CN/SAN hostname match, and X.509 validity/expiry directly from `testssl.sh` `serverDefaults` JSON output.

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `TLS-04` — ASVS V9.2.1 (L2); CA/Browser Forum Baseline Requirements (`Web_Application`)
- **Evidence:** Machine-readable (JSON) TLS scanner output for every declared host (`output/tls-scan.json`, `output/testssl-tls04-raw.json`).
- **Test Procedure:** Run `testssl.sh` (`--ssl-native -S`) against each declared host/TLS port and inspect certificate chain trust, hostname match, and validity period.
- **Verification:**
  - **PASS:** Chain validates to a trusted root (`cert_chain_of_trust` `OK`), certificate is not expired at scan time, and CN/SAN matches the target host (`cert_trust` `OK`); remaining lifetime under 30 days is reported **informational** (`warnings`) without failing.
  - **FAIL:** Chain validation error (e.g., self-signed / untrusted issuer), expired certificate, hostname/SAN mismatch, or absent certificate (cleartext HTTP).

## Acceptance Criteria
1. `run_testssl_scan` supports optional `extra_args` (e.g., `--add-ca` for isolated PKI unit testing while production scans strictly validate against the public root store).
2. `parse_testssl_certificate(scan_result, target_port)` parses `serverDefaults` (`cert_commonName`, `cert_subjectAltName`, `cert_trust`, `cert_chain_of_trust`, `cert_notBefore`, `cert_notAfter`, `cert_expirationStatus`, `cert_caIssuers`).
3. `evaluate_tls04_certificate_validation(...)` runs `testssl.sh --ssl-native -S` on HTTPS/TLS hosts and exits quickly with `FAIL` (`present=False`) on cleartext HTTP targets.
4. Unit tests (`test_iteration92_tls04_guide_tooling`) verify with real `testssl.sh 3.2.2`:
   - `PASS` with valid CA-signed cert (`>= 30` days),
   - `PASS` + informational `< 30 days` warning on valid CA-signed cert with `< 30` days lifetime,
   - `FAIL` on self-signed / untrusted CA cert,
   - `FAIL` on hostname/SAN mismatch,
   - `FAIL` on cleartext HTTP endpoint.
5. Live OWASP Juice Shop (`http://localhost:3000`) scan confirms `TLS-04 = FAIL` cleanly.

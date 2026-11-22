# SDD 093 — TLS-05: Guide-Compliant Reference Tooling (`testssl.sh --ssl-native -h`)

## Objective
Align control **TLS-05** (`` `Strict-Transport-Security` present with `max-age` >= 31536000 ``) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 3 reference tooling (`testssl.sh`), extracting `HSTS_time`, `HSTS_subdomains`, and `HSTS_preload` directly from `testssl.sh` `headerResponse` JSON output alongside multi-endpoint HTTPS header verification.

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `TLS-05` — ASVS V14.4.5 (L1); RFC 6797 (`Web_Application`)
- **Evidence:** Machine-readable (JSON) TLS scanner output for every declared host (`output/tls-scan.json`, `output/testssl-tls05-raw.json`).
- **Test Procedure:** Run `testssl.sh` (`--ssl-native -h`) against each declared host/TLS port, read `HSTS_time` from `headerResponse`, and confirm HSTS consistency across HTML and API endpoints over HTTPS.
- **Verification:**
  - **PASS:** Target serves HTTPS and `HSTS_time >= 31536000` on every tested endpoint (reported by both `testssl.sh -h` and multi-endpoint HTTPS probes).
  - **FAIL:** `Strict-Transport-Security` header is absent on any endpoint, `max-age` (`HSTS_time`) `< 31536000`, or target serves cleartext HTTP (RFC 6797 §7.2).

## Acceptance Criteria
1. `parse_testssl_hsts(scan_result)` parses `headerResponse` (`HSTS_time` seconds, `HSTS`, `HSTS_subdomains`, `HSTS_preload`) from `testssl.sh --ssl-native -h`.
2. `evaluate_tls05_hsts_enforcement(...)` runs `testssl.sh --ssl-native -h` on HTTPS/TLS hosts (`output/testssl-tls05-raw.json`), checks `/`, `/api/Products`, `/rest/admin/application-configuration`, and fails fast cleanly on cleartext HTTP endpoints.
3. Unit tests (`test_iteration93_tls05_guide_tooling`) verify with real `testssl.sh 3.2.2`:
   - `PASS` on HTTPS server returning `Strict-Transport-Security: max-age=31536000; includeSubDomains`,
   - `FAIL` on HTTPS server returning `max-age=600` (`< 31536000`),
   - `FAIL` on HTTPS server missing `Strict-Transport-Security`,
   - `FAIL` on cleartext HTTP server even if sending HSTS header (RFC 6797 §7.2).
4. Live OWASP Juice Shop (`http://localhost:3000`) scan confirms `TLS-05 = FAIL` (`HSTS_time = 0`).

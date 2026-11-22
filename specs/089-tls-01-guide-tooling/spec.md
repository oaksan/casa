# SDD 089 — TLS-01: Guide-Compliant Reference Tooling (`testssl.sh`)

## Objective
Align control **TLS-01** (`TLS enforced on all endpoints; no cleartext fallback; HTTP redirects to HTTPS`) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 3 tooling (`testssl.sh`) while maintaining machine-readable JSON evidence (`output/tls-scan.json`, `output/testssl-raw.json`) and strict port-80/cleartext `3xx` -> `https://<same-host>` verification.

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `TLS-01` — ASVS V9.1.1 (L1) (`Web_Application`)
- **Evidence:** Machine-readable (JSON) TLS scanner output for every declared host (`output/tls-scan.json` + `output/testssl-raw.json`).
- **Test Procedure:** Run `testssl.sh` against every declared host's TLS port (`443` or declared HTTPS port) and probe cleartext HTTP endpoints without following redirects (`follow_redirects=False`).
- **Verification:**
  - **PASS:** Host completes TLS handshake via `testssl.sh` (at least one TLS protocol offered, zero `FATAL` `scanProblem`), declared URL uses `https://`, and every cleartext HTTP probe either fails connection (`status == 0`) or returns a `3xx` `Location` header pointing to `https://<same-host>`.
  - **FAIL:** `testssl.sh` reports `FATAL` `scanProblem` / handshake failure, declared URL uses cleartext `http://`, or >= 1 cleartext HTTP request responds without a valid `3xx` `Location` to `https://<same-host>`.

## Acceptance Criteria
1. Official `testssl.sh` (`3.2.2`) is invoked programmatically via `TESTSSL_BIN` (`--quiet --warnings batch --color 0 --ip one --connect-timeout 2 --openssl-timeout 2 -p --jsonfile-pretty`) with raw JSON persisted.
2. `evaluate_tls01_transport_enforcement(...)` validates TLS handshake via `testssl.sh` JSON (`scanResult`) plus cleartext no-redirect HTTP probes (`/`, `/rest/user/login`, `/api/Products`).
3. Unit tests (`test_iteration89_tls01_guide_tooling`) verify both `PASS` (TLS + refused/3xx-to-HTTPS cleartext) and `FAIL` (TLS + HTTP 200 cleartext leak, and HTTP-only target with closed TLS port) using real `testssl.sh` against localhost ephemeral servers.
4. Live OWASP Juice Shop (`http://localhost:3000`) scan retains real `testssl.sh` evidence in `output/tls-scan.json` and `output/testssl-raw.json` with `TLS-01 = FAIL`.

# SDD 094 — TLS-06: Guide-Compliant Reference Tooling (`testssl.sh -H -I -T -C`)

## Objective
Align control **TLS-06** (`No known TLS implementation vulnerabilities (Heartbleed, ROBOT, insecure renegotiation, CRIME)`) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 3 reference tooling (`testssl.sh`), reading `vulnerabilities` directly from `testssl.sh` JSON output (`-H -I -T -C`, ~13.5s) supplemented with deterministic `secure_renego` (`openssl s_client`) and `ROBOT` (`cipherlist_STRONG_NOFS` / `kRSA`) verification so scans never stall.

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `TLS-06` — *ADA-defined*; OWASP WSTG-CRYP-01 (`Web_Application`)
- **Evidence:** Machine-readable (JSON) TLS scanner output for every declared host (`output/tls-scan.json`, `output/testssl-tls06-raw.json`).
- **Test Procedure:** Run `testssl.sh` vulnerability checks (`-H` Heartbleed, `-I` CCS Injection, `-T` Ticketbleed, `-C` CRIME_TLS) against every declared host/TLS port, alongside `secure_renego` and `ROBOT` (`kRSA`) evaluation.
- **Verification:**
  - **PASS:** TLS is active and zero entries in `.vulnerabilities` have severity `HIGH` or `CRITICAL` (`heartbleed`, `ROBOT`, `secure_renego`, `CRIME_TLS`, `ticketbleed` included); lower-severity findings are informational.
  - **FAIL:** `>= 1` vulnerability entry at severity `HIGH` or `CRITICAL`, or endpoint lacks TLS.

## Acceptance Criteria
1. `parse_testssl_vulnerabilities(scan_result, target_port)` parses `vulnerabilities` from `testssl.sh` JSON into `highOrCriticalFindings` (`HIGH`/`CRITICAL`) and `informationalFindings` (`MEDIUM`/`LOW`/`WARN`).
2. `evaluate_tls06_vulnerabilities(...)` executes `run_testssl_scan(host, port, checks=("-H", "-I", "-T", "-C"), timeout_sec=30)` on HTTPS/TLS hosts (`output/testssl-tls06-raw.json`), evaluates `secure_renego` + `ROBOT` without blocking sockets, and fails fast on cleartext HTTP endpoints (`tls_endpoint_missing`).
3. Unit tests (`test_iteration94_tls06_guide_tooling`) run cleanly in <25s and verify `PASS` (`testssl.sh -H -I -T -C`), informational low-severity (`PASS`), `HIGH`/`CRITICAL` (`FAIL`), and cleartext HTTP (`FAIL`).
4. Live OWASP Juice Shop (`http://localhost:3000`) scan confirms `TLS-06 = FAIL` cleanly.

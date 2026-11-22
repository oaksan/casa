# SDD 090 — TLS-02: Guide-Compliant Reference Tooling (`testssl.sh -p`)

## Objective
Align control **TLS-02** (`Only TLS 1.2 and TLS 1.3 enabled; SSLv3, TLS 1.0 and TLS 1.1 rejected`) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 3 tooling (`testssl.sh -p`), deriving the `.protocols` matrix directly from official `testssl.sh` JSON output (`SSLv2`, `SSLv3`, `TLS1`, `TLS1_1`, `TLS1_2`, `TLS1_3`).

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `TLS-02` — ASVS V9.1.3 (L1); NIST SP 800-52 Rev.2 (`Web_Application`)
- **Evidence:** Machine-readable (JSON) TLS scanner output for every declared host (`output/tls-scan.json`, `output/testssl-raw.json`).
- **Test Procedure:** Run `testssl.sh` (`-p`) against each declared host/TLS port and read offered protocol versions from `.protocols`.
- **Verification:**
  - **PASS:** `.protocols` reports `TLS 1.2` or `TLS 1.3` as `offered`, and `SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1` all `not offered`.
  - **FAIL:** Any of `SSLv2`, `SSLv3`, `TLS 1.0`, or `TLS 1.1` is reported `offered`, or neither `TLS 1.2` nor `TLS 1.3` completes a handshake.

## Acceptance Criteria
1. `parse_testssl_protocols(scan_result)` maps `testssl.sh` JSON entries (`SSLv2`, `SSLv3`, `TLS1`, `TLS1_1`, `TLS1_2`, `TLS1_3`) deterministically to `.protocols` (`SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`, `TLS 1.2`, `TLS 1.3`).
2. `evaluate_tls02_protocol_enforcement(...)` runs or reuses `run_testssl_scan(..., checks=("-p",))` when probing TLS targets, while failing cleanly when a declared target runs exclusively over cleartext HTTP (`modernOffered=[]`).
3. Unit tests (`test_iteration90_tls02_guide_tooling`) verify with real `testssl.sh 3.2.2`:
   - `PASS` on a TLS 1.2/1.3-only server,
   - `FAIL` when a legacy TLS 1.0 / TLS 1.1 server (`ALL:@SECLEVEL=0`) is exposed alongside TLS 1.2/1.3,
   - `FAIL` on a plain HTTP cleartext server.
4. Live OWASP Juice Shop (`http://localhost:3000`) scan confirms `TLS-02 = FAIL` cleanly.

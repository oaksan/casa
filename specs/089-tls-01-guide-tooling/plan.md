# Plan 089 — TLS-01 (`testssl.sh` + Cleartext Enforcement)

## Architecture
1. **`TESTSSL_BIN` & `run_testssl_scan` (`casa_audit/scanner.py`):**
   - Resolve `testssl.sh` binary via `shutil.which("testssl.sh") or shutil.which("testssl") or "/home/user/.local/bin/testssl.sh"`.
   - Execute `testssl.sh` with `--quiet --warnings batch --color 0 --ip one --connect-timeout 2 --openssl-timeout 2 -p --jsonfile-pretty <raw_json> <host>:<port>` (`stdin=subprocess.DEVNULL`, `timeout=35`).
   - Parse `"version"`, `"openssl"`, `"scanTime"`, and `"scanResult"` cleanly, distinguishing reachable TLS endpoints (`protocols` offering TLS) from unreachable targets (`id == "scanProblem"` / `"severity": "FATAL"`).
2. **`evaluate_tls01_transport_enforcement(...)`:**
   - Reusable entry point used by both `run_dynamic_and_protocol_checks` and `test_iteration89_tls01_guide_tooling`.
   - Combines `run_testssl_scan` output with `follow_redirects=False` probes on `/`, `/rest/user/login`, and `/api/Products` (accepting custom `http_probe` and port overrides for deterministic unit testing without root port-80 bind).
3. **`tls-scan.json` & Tool Metadata:**
   - Persist `output/testssl-raw.json` and enrich `output/tls-scan.json` with official `testssl` object (`binary`, `version`, `openssl`, `returncode`, `rawJsonPath`, `scanTime`, `scanResult`) while keeping full schema compatibility for `TLS-02..TLS-06`.
   - Set `results["TLS-01"]["tool"]` to reference `testssl.sh <version>`.
4. **Validation & Documentation:**
   - Add `test_iteration89_tls01_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
   - Document iteration in `docs/justificativa2.txt` (`CONTROLE 19/61: TLS-01 (Iteração SDD 089)`).
   - Run full `unittest` suite, then run live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000`).

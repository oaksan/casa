# SDD 096 — CFG-02: Guide-Compliant Reference Tooling (`Nuclei 3.11.1 + OWASP ZAP 2.17.0`)

## Objective
Align control **CFG-02** (`Framework and server debug modes disabled in production`) in `casa-assessment/casa_audit/scanner.py` with the official **CASA 3.0 (AL1) Test Guide** Domain 4 reference tooling (**OWASP ZAP, nuclei**), executing real ProjectDiscovery **Nuclei 3.11.1** templates (`rules/nuclei_cfg02/*.yaml`) combined with OWASP ZAP `2.17.0` debug/error alerts (`10023`, `90022`, `40042`).

## Normative Basis (`CASA/CASA 3.0 (AL1) Test Guide.md`)
- **Control:** `CFG-02` — ASVS V14.3.2 (L1) (`Web_Application`)
- **Evidence:** DAST findings in SARIF 2.1.0 (`output/dast-findings.sarif`, `output/nuclei-cfg02.sarif`, `output/zap-findings.sarif`) + HAR 1.2 + `output/nuclei-cfg02.jsonl`.
- **Test Procedure:** Request known framework debug, profiler, actuator, and error-traceback endpoints on every declared host using `nuclei` and `ZAP`.
- **Verification:**
  - **PASS:** Zero debug consoles, profilers, or actuators return 2xx unauthenticated, and zero responses carry framework debug/traceback markers (Werkzeug, Django `DEBUG = True`, Rails exception pages, ASP.NET detailed errors, Express stacktrace).
  - **FAIL:** `>= 1` debug endpoint returns 2xx unauthenticated or `>= 1` response carries a framework debug marker.

## Acceptance Criteria
1. Official ProjectDiscovery **Nuclei `v3.11.1`** installed at `/home/user/.local/bin/nuclei`, and `NUCLEI_BIN` + `run_nuclei_scan(...)` implemented in `casa_audit/scanner.py` with `-duc`, `-jle`, and native `-se` SARIF export.
2. Verified Nuclei YAML template suite in `casa-assessment/rules/nuclei_cfg02/` covering Prometheus `/metrics`, Swagger/OpenAPI docs, Admin App Config, Spring Boot Actuator, multi-framework consoles/profilers (Django, Werkzeug, Symfony, Rails, Go pprof, ELMAH, phpinfo, mod_status, GraphiQL), SPA false-positive negation (`!<app-root`), and malformed-JSON / error traceback probes.
3. `evaluate_cfg02_debug_modes(...)` merges Nuclei JSONL matches with ZAP `10023`/`90022`/`40042` alerts and emits `CASA3-CFG-02` into `output/dast-findings.sarif`.
4. Unit tests (`test_iteration96_cfg02_guide_tooling`) validate both `PASS` (hardened + SPA catch-all) and `FAIL` (Spring Actuator + Werkzeug + Django `DEBUG = True`) using real Nuclei `3.11.1`.
5. Live OWASP Juice Shop (`http://localhost:3000`) scan retains real `output/nuclei-cfg02.sarif` + `output/nuclei-cfg02.jsonl` and confirms `CFG-02 = FAIL`.

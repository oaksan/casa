# Implementation Plan 102 — CFG-08 (`OWASP ZAP`)

1. Add `evaluate_cfg08_cors(...)` in `casa-assessment/casa_audit/scanner.py` running active multi-origin CORS probes (`https://evil.example.com`, `null`, `https://not<host>`) across public, authenticated, admin, and `OPTIONS` preflight routes while correlating OWASP ZAP `2.17.0` Passive Rule `10098` (*Cross-Domain Misconfiguration*).
2. Wire `results["CFG-08"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration102_cfg08_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering strict allowlist (`PASS` via real ZAP `2.17.0`), permissive wildcard on sensitive routes caught by ZAP Rule `10098` (`FAIL`), `null`/foreign/suffix reflection (`FAIL`), and wildcard + `Access-Control-Allow-Credentials: true` (`FAIL`).
4. Append `CONTROLE 32/61: CFG-08 (Iteração SDD 102)` to `docs/justificativa2.txt`.
5. Run the full `unittest` suite (`35` tests) to completion, execute the live OWASP Juice Shop scan, commit, tag `sdd-102`, and push.

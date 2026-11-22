# Implementation Plan 101 — CFG-07 (`OWASP ZAP`)

1. Add `evaluate_cfg07_anti_caching(...)` in `casa-assessment/casa_audit/scanner.py` performing ephemeral user authentication (`POST /api/Users/` + `POST /rest/user/login`), probing all authenticated/sensitive routes for strict `no-store` in `Cache-Control`, and correlating OWASP ZAP `2.17.0` passive rules `10049`/`10015` (filtered to authenticated/sensitive targets when `no-store` is absent).
2. Wire `results["CFG-07"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration101_cfg07_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering strict `Cache-Control: no-store` (`PASS` via real ZAP `2.17.0`), missing `Cache-Control` caught by real ZAP Rule `10049`/`10015` (`FAIL`), and `Cache-Control: private, max-age=0` without `no-store` (`FAIL`).
4. Append `CONTROLE 31/61: CFG-07 (Iteração SDD 101)` to `docs/justificativa2.txt`.
5. Run the full `unittest` suite (`34` tests) to completion, execute the live OWASP Juice Shop scan, commit, tag `sdd-101`, and push.

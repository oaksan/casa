# Implementation Plan 103 — CFG-09 (`OWASP ZAP`)

1. Add `evaluate_cfg09_error_disclosure(...)` in `casa-assessment/casa_audit/scanner.py` executing malformed-type, SQL-syntax, ENOENT, unauthenticated-type, schema-error, and 200 KB oversize JSON probes across crawled `4xx`/`5xx` exchanges, classifying leaks (`stack_frame`, `filesystem_path`, `sql_fragment`, `internal_routing_or_module`) and correlating OWASP ZAP `2.17.0` Rule `90022` (*Application Error Disclosure*).
2. Wire `results["CFG-09"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration103_cfg09_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering generic 4xx/5xx (`PASS` via real ZAP `2.17.0`), SQL/traceback error caught by ZAP Rule `90022` (`FAIL`), and filesystem-path + internal-module leaks on `404`/`413` (`FAIL`).
4. Append `CONTROLE 33/61: CFG-09 (Iteração SDD 103)` to `docs/justificativa2.txt`.
5. Run the full `unittest` suite (`36` tests) to completion, execute the live OWASP Juice Shop scan, commit, tag `sdd-103`, and push.

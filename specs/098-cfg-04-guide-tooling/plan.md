# Implementation Plan 098 — CFG-04 (`csp-evaluator`)

1. Install official Google `csp_evaluator` (`1.1.8`) under `/home/user/.local/share/csp_evaluator`.
2. Add `NODE_BIN` and `CSP_EVALUATOR_DIR` constants in `casa-assessment/casa_audit/scanner.py`.
3. Add `run_csp_evaluator_batch` and `evaluate_cfg04_csp` in `casa-assessment/casa_audit/scanner.py` invoking Google `csp_evaluator` (`CspParser` + `CspEvaluator`) on every unique enforcing `Content-Security-Policy` across crawled HTML routes, persisting `output/csp-evaluator.json` and filtering findings against the effective `script-src` (`script-src` or `default-src` fallback) for `MISSING_DIRECTIVES` (`300`), `SCRIPT_UNSAFE_INLINE` (`301`), `SCRIPT_UNSAFE_EVAL` (`302`), `PLAIN_URL_SCHEMES` (`303`, `data:`), and `PLAIN_WILDCARD` (`304`, `*`).
4. Wire `CFG-04` in `run_dynamic_and_protocol_checks` using `evaluate_cfg04_csp` and correlate OWASP ZAP plugin `10038`/`10055` telemetry.
5. Add `test_iteration98_cfg04_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering clean strict CSP (`PASS`), `unsafe-inline` / `unsafe-eval` / `data:` / `*` / `Report-Only` / missing CSP (`FAIL`), and `style-src 'unsafe-inline'` alongside safe `script-src 'self'` (`PASS`).
6. Document `CONTROLE 28/61: CFG-04 (Iteração SDD 098)` in `docs/justificativa2.txt`.
7. Execute the full `unittest` suite (`31` tests), run live scan against OWASP Juice Shop, commit, tag `sdd-098`, and push.

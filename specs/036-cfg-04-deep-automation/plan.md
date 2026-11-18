# Implementation Plan — Iteration 036 (`CFG-04`)

1. Replace the root-only `CFG-04` header check in `casa-assessment/casa_audit/scanner.py` with `parse_csp_directives` evaluating every unique HTML response across `crawled_exchanges`.
2. Resolve effective `script-src` vs `default-src` fallback and reject `unsafe-inline`, `unsafe-eval`, `*`, `data:`, or missing/report-only CSPs.
3. Append `CASA3-CFG-04` results to `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-036`, and push.

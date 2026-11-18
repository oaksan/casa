# Implementation Plan — Iteration 041 (`CFG-09`)

1. Expand `CFG-09` in `casa-assessment/casa_audit/scanner.py` with 6 forced-error probes covering malformed types, oversize JSON payload (`413`), missing file `404 ENOENT`, unauthenticated `401`, eval error, and SQL syntax error.
2. Audit all unique `4xx`/`5xx` responses across `crawled_exchanges` against 4 disclosure classes (`stack_frame`, `filesystem_path`, `sql_fragment`, `internal_routing_or_module`).
3. Emit `CASA3-CFG-09` entries to `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-041`, and push.

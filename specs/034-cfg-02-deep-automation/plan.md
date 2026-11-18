# Implementation Plan — Iteration 034 (`CFG-02`)

1. Replace the `/metrics`-only `CFG-02` check in `casa-assessment/casa_audit/scanner.py` with a 19-endpoint framework debug/profiler/actuator probe list plus `is_spa_fallback` guard.
2. Add active traceback-triggering probes (`POST /rest/user/login` malformed JSON + `GET /rest/products/search?q='`) matching Express `errorhandler`, Werkzeug, Django, Rails, ASP.NET, and Python stacktrace markers.
3. Append `CASA3-CFG-02` findings to `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-034`, and push.

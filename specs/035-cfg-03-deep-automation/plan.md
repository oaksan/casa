# Implementation Plan — Iteration 035 (`CFG-03`)

1. Record HTTP method, URL, status, headers, and response body in `crawled_exchanges` inside `http_probe` (`casa-assessment/casa_audit/scanner.py`).
2. Probe `/rest/admin/application-version` and `/version`, then scan every exchange in `crawled_exchanges` for `[A-Za-z-]+/[0-9]+\.[0-9]+` tokens, stack headers (`X-Powered-By`, `X-AspNet-Version`, etc.), runtime metrics, JSON release versions, HTML generator tags, and traceback dependency paths.
3. Append `CASA3-CFG-03` results to `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-035`, and push.

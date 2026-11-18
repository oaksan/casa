# Implementation Plan — Iteration 047 (`AUT-04`)

1. Redact sensitive query parameter values in `har_entries["request"]["url"]` inside `http_probe` (`casa-assessment/casa_audit/scanner.py`).
2. Replace the static `AUT-04` stub with a crawl-wide URL/query/fragment/`Referer` inspector, active CWE-598 `GET /rest/user/change-password` probe with ephemeral user credentials, and OAuth `#access_token=` fragment inspection.
3. Emit `CASA3-AUT-04` results into `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-047`, and push.

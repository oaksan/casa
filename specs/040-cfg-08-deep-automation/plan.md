# Implementation Plan — Iteration 040 (`CFG-08`)

1. Replace the single-origin `CFG-08` probe in `casa-assessment/casa_audit/scanner.py` with a 21-probe CORS matrix across 7 endpoints (public, authenticated/sensitive, `OPTIONS` preflight) and 3 origins (foreign, `null`, domain suffix-sharing).
2. Detect origin reflection, `null` acceptance, `*` + `Allow-Credentials: true`, and wildcard `*` without strict allowlist on sensitive endpoints.
3. Append deduplicated `CASA3-CFG-08` results to `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-040`, and push.

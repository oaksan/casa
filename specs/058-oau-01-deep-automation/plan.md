# Implementation Plan — Iteration 058 (`OAU-01`)

1. Fetch served non-polyfill JS bundles from `root_body` into `oauth_bundle_texts` at the start of Domain 7 (`casa-assessment/casa_audit/scanner.py`).
2. Inspect both live bundles (`http://localhost:3000/main.js`) and client OAuth source files for `response_type != code`, `grant_type=password` (ROPC), and client-side `#access_token=` handling.
3. Emit `CASA3-OAU-01` results into `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-058`, and push.

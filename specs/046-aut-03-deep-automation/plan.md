# Implementation Plan — Iteration 046 (`AUT-03`)

1. Replace the static `bool(jwt_token)` `AUT-03` check in `casa-assessment/casa_audit/scanner.py` with full pre-auth cookie capture, fixation cookie injection on `POST /rest/user/login`, token rotation comparison, and post-login replay against protected endpoints.
2. Emit `CASA3-AUT-03` entries to `dast_sarif_results` (`output/dast-findings.sarif`) when unchanged or pre-auth identifiers remain accepted.
3. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-046`, and push.

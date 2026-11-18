# Implementation Plan — Iteration 059 (`OAU-02`)

1. Replace `"code_challenge" in login_txt` in `casa-assessment/casa_audit/scanner.py` with full RFC 7636 PKCE inspection across `combined_oauth_sources` (`main.js` live bundle + source files).
2. Check `code_challenge`, `code_challenge_method=S256` (rejecting `plain`), minimum length `>= 43`, and `code_verifier`, emitting `CASA3-OAU-02` into `dast_sarif_results` (`output/dast-findings.sarif`).
3. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-059`, and push.

# Implementation Plan — Iteration 042 (`CFG-10`)

1. Import `difflib` in `casa-assessment/casa_audit/scanner.py` and implement `lcs_line_similarity(txt_a, txt_b)` matching the CASA 3.0 AL1 whitespace-normalized line LCS ratio specification.
2. Replace the single `/rest/admin/application-configuration` probe with differential auth-vs-unauth replay across 6 authenticated routes and 12 admin/operational wordlist paths (36 HTTP probes).
3. Emit `CASA3-CFG-10` results to `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-042`, and push.

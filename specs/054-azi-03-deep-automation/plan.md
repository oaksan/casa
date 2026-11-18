# Implementation Plan — Iteration 054 (`AZI-03`)

1. Replace the single-probe `AZI-03` block in `casa-assessment/casa_audit/scanner.py` with an 8-probe SQLi (auth bypass, differential boolean `0 -> 28`, error-based) and non-destructive NoSQL (`$where` `' || true || '` `1 -> 3`, JSON `$ne`/`$regex`) scanner.
2. Emit `CASA3-AZI-03` entries into `dast_sarif_results` (`output/dast-findings.sarif`).
3. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-054`, and push.

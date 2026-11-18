# Implementation Plan — Iteration 037 (`CFG-05`)

1. Replace the root-only `CFG-05` header check in `casa-assessment/casa_audit/scanner.py` with `has_valid_frame_ancestors` and iterate across all entries in `html_routes_seen`.
2. Append any failing HTML routes under `CASA3-CFG-05` into `dast_sarif_results` (`output/dast-findings.sarif`).
3. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-037`, and push.

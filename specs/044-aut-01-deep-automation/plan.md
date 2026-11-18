# Implementation Plan — Iteration 044 (`AUT-01`)

1. Update `http_probe` in `casa-assessment/casa_audit/scanner.py` to redact `authorization`, `cookie`, `set-cookie`, and `x-api-key` headers when recording `har_entries` (`output/dast-capture.har`).
2. Replace the single-pair `AUT-01` check with login-surface probing + a 12-pair default/vendor credential corpus (`product_default_corpus + generic_default_corpus`) masking passwords in logs/SARIF.
3. Emit `CASA3-AUT-01` results to `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-044`, and push.

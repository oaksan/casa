# Implementation Plan — Iteration 056 (`AZI-05`)

1. Replace the single `/ftp/package.json.bak%2500.md` check in `casa-assessment/casa_audit/scanner.py` with a 9-probe matrix covering encoded, double-encoded, poison null-byte, absolute, and UNC traversal forms plus an ephemeral `RfiCallbackHandler` listener probing `POST /profile/image/url`.
2. Emit `CASA3-AZI-05` findings (`CWE-22`, `CWE-98`) into `dast_sarif_results` (`output/dast-findings.sarif`).
3. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-056`, and push.

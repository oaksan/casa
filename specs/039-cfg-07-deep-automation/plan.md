# Implementation Plan — Iteration 039 (`CFG-07`)

1. Replace the anonymous single-route `CFG-07` check in `casa-assessment/casa_audit/scanner.py` with active ephemeral user registration/login and authenticated probing across 9 authenticated and sensitive endpoints.
2. Parse `Cache-Control` comma-separated directives strictly requiring `no-store`.
3. Emit `CASA3-CFG-07` SARIF 2.1.0 entries into `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-039`, and push.

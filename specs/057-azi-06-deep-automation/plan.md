# Implementation Plan — Iteration 057 (`AZI-06`)

1. Replace the static `routes/redirect.ts` grep in `casa-assessment/casa_audit/scanner.py` with a 10-probe `follow_redirects=False` open-redirect & duplicated-parameter HPP differential verifier.
2. Parse `3xx Location` hostnames strictly and detect Express query-array coercion (`406 -> 302`) on `/redirect?to=...&to=...` plus duplicate ID checks on `/rest/basket/{id}`.
3. Preserve `open_redir_vuln` for `OAU-03` and emit `CASA3-AZI-06` findings into `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`), update `docs/justificativa.txt` and `tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-057`, and push.

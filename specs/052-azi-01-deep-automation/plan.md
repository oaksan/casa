# Implementation Plan — Iteration 052 (`AZI-01`)

1. Replace the static `csurf` check in `casa-assessment/casa_audit/scanner.py` with a live 3-mode cross-origin Cookie-only CSRF replay harness against `POST /profile` using two distinct valid sessions (`session_a_tok`, `session_b_tok`) plus re-read state mutation confirmation (`GET /profile`).
2. Inspect all crawl `Set-Cookie` headers for `SameSite=None` and emit `CASA3-AZI-01` results into `dast_sarif_results` (`output/dast-findings.sarif`).
3. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-052`, and push.

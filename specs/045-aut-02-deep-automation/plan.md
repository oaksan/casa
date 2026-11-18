# Implementation Plan — Iteration 045 (`AUT-02`)

1. Import `http.client` and `collections.Counter` in `casa-assessment/casa_audit/scanner.py`.
2. Replace single-token Shannon check with a 200-login keep-alive collection harness computing token uniqueness and NIST SP 800-90B MCV min-entropy (`-log2(max_freq / N)` + positional MCV min-entropy when all 200 are unique).
3. Emit `CASA3-AUT-02` findings to `dast_sarif_results` (`output/dast-findings.sarif`) with redacted HAR sampling.
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-045`, and push.

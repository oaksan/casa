# Implementation Plan — Iteration 038 (`CFG-06`)

1. Replace the root-only `CFG-06` check in `casa-assessment/casa_audit/scanner.py` with a crawl-wide 100%-compliance audit across all unique HTTP responses (`status > 0`) in `crawled_exchanges` (including static `/ftp/legal.md`).
2. Emit `CASA3-CFG-06` findings to `dast_sarif_results` (`output/dast-findings.sarif`).
3. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-038`, and push.

# Implementation Plan — Iteration 033 (`CFG-01`)

1. Initialize `dast_sarif_path` (`output/dast-findings.sarif`) and `dast_sarif_results` in `run_dynamic_and_protocol_checks` (`casa-assessment/casa_audit/scanner.py`).
2. Replace the single `/ftp` probe in `CFG-01` with `parse_directory_index(...)` (HTML autoindex + S3 `ListBucketResult` XML) and a bounded breadth-first prefix spider/crawler seeded from `/`, `robots.txt`, and sensitive directory prefixes.
3. Emit `CASA3-CFG-01` SARIF 2.1.0 results and write `output/dast-findings.sarif` next to `output/dast-capture.har`.
4. Verify empirically against live OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-033`, and push.

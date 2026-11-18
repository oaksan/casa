# Implementation Plan — Iteration 051 (`AUT-08`)

1. Add standalone headless Chrome CDP automation helper `casa-assessment/scripts/headless_storage_dump.js` using Node.js 24 built-in `WebSocket` + `/usr/bin/google-chrome`.
2. Update `AUT-08` in `casa-assessment/casa_audit/scanner.py` with `luhn_check` and `scan_storage_snapshot`, invoking headless browser dump before and after UI logout on a canary account (while preserving `local_storage_hits` for `OAU-07`).
3. Emit masked `CASA3-AUT-08` results into `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-051`, and push.

# Implementation Plan — Iteration 043 (`CFG-11`)

1. Replace the static `CFG-11` stub in `casa-assessment/casa_audit/scanner.py` with `run_dig_query` (`dig` `CNAME`, `A`, `AAAA`) + `socket.getaddrinfo` resolution traversing CNAME chains up to 8 hops.
2. Evaluate CNAME targets, DNS status (`NXDOMAIN`), and HTTP response banners against 16 cloud takeover fingerprints.
3. Emit any detected findings under `CASA3-CFG-11` in `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-043`, and push.

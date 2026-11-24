# Implementation Plan 113 — AUT-08 (`Headless Chrome CDP Storage Dump Harness`)

1. Enhance `casa-assessment/scripts/headless_storage_dump.js` to extract `IndexedDB` object-store entries (in addition to DB metadata), support generic HTML/Angular login & logout selectors, and complete cleanly for compliant HttpOnly-only web apps as well as Juice Shop.
2. Extract `_luhn_check`, `_scan_storage_snapshot`, and `evaluate_aut08_client_storage(...)` in `casa-assessment/casa_audit/scanner.py` supporting headless Chrome CDP execution, observed tokens + Luhn PAN + seeded canary + IdP profile matching across pre- and post-logout dumps, redacted `output/aut08-storage-dump.json`, redacted `output/aut08-replayed.har`, and SARIF 2.1.0 (`CASA3-AUT-08`).
3. Wire `results["AUT-08"]` inside `run_dynamic_and_protocol_checks`.
4. Add `test_iteration113_aut08_guide_tooling` in `casa-assessment/tests/test_iteration1.py` exercising real `/usr/bin/google-chrome` via `headless_storage_dump.js`:
   - **PASS:** Compliant HttpOnly-cookie web app storing zero tokens/canaries/PANs in `localStorage`/`sessionStorage`/`IndexedDB`/`document.cookie` (`[REDACTED]` HAR + JSON dump verified);
   - **FAIL (Pre-logout JWT + Canary + Luhn PAN):** Real headless Chrome captures JWT in `localStorage` and seeded canary in `sessionStorage`;
   - **FAIL (Post-logout survivor):** Token/auth material persists after logout click -> `postLogoutSurvivors >= 1` (`CASA3-AUT-08`).
5. Append `CONTROLE 43/61: AUT-08 (Iteração SDD 113)` to `docs/justificativa2.txt`.
6. Run full `unittest` suite (`46` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`) with refreshed `casa_audit` daemon, check off `tasks.md`, commit, tag `sdd-113`, and push `main` + tags.

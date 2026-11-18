# Plan — SDD 065: OAU-08 Deep Automation

1. Update `http_probe` HAR redaction in `casa-assessment/casa_audit/scanner.py` to retain `Bearer [REDACTED]` / `DPoP [REDACTED]` scheme prefixes cleanly.
2. Replace the fake `OAU-08` stub `PASS` with full HAR 1.2 header/URL inspection, active backend query-token probes (`?access_token=` / `?token=`), and live JS bundle + client routing transport checks (`user.service.ts`, `app.routing.ts`, `main.js`).
3. Validate empirically against OWASP Juice Shop (`http://localhost:3000`) confirming `FAIL` (4 `CASA3-OAU-08` SARIF findings across 282 HAR entries & 89 Bearer requests).
4. Document Control 57/61 in `docs/justificativa.txt`, assert in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-065`.

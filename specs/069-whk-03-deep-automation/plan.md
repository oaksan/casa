# Plan — SDD 069: WHK-03 Deep Automation (Control 61/61)

1. Import `ipaddress` and add `evaluate_whk03_ssrf_and_signing_secrets` in `casa-assessment/casa_audit/scanner.py`.
2. Extend `discover_webhook_facilities` with callback-registration route probes and wire `results["WHK-03"]` inside Domain 8.
3. Validate empirically against OWASP Juice Shop (`Not_Covered` across 657 repo files & 10 POST probes) and live SSRF callback listener / signing-secret fixtures (`FAIL` & `PASS`).
4. Document Control 61/61 in `docs/justificativa.txt`, assert in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-069`.

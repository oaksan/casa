# Plan — SDD 067: WHK-01 Deep Automation

1. Add `discover_webhook_facilities` and `evaluate_whk01_delivery_tls` in `casa-assessment/casa_audit/scanner.py`.
2. Wire Domain 8 discovery and `WHK-01` verification in `run_dynamic_and_protocol_checks`, emitting `CASA3-WHK-01` SARIF findings and referencing HAR 1.2 + `tls-scan.json`.
3. Validate empirically against live OWASP Juice Shop (`Not_Covered` across 657 repo files & 7 HTTP POST probes) and live cleartext/HTTPS webhook server fixtures (`FAIL` & `PASS`).
4. Document Control 59/61 in `docs/justificativa.txt`, assert in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-067`.

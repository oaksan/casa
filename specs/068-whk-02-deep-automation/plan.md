# Plan — SDD 068: WHK-02 Deep Automation

1. Add `evaluate_whk02_hmac_and_timing_safe` in `casa-assessment/casa_audit/scanner.py` implementing the 4-vector signed payload harness and static MAC / timing-safe call-site auditor.
2. Wire `results["WHK-02"]` in Domain 8 emitting `CASA3-WHK-02` SARIF results and referencing HAR 1.2 + `tls-scan.json`.
3. Validate empirically against OWASP Juice Shop (`Not_Covered` across 657 repo files & 7 discovery probes) and vulnerable/compliant webhook fixtures (`FAIL` & `PASS`).
4. Document Control 60/61 in `docs/justificativa.txt`, add assertions in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-068`.

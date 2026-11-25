# Spec 130 — WHK-02 Guide-Compliant Tooling

- **Control:** `WHK-02` (60/61) — Payloads are authenticated with HMAC-SHA256 or stronger, verified using a timing-safe comparison (`CASA v2.1.1 §7.2.1, §7.2.2; CWE-208`, Surface: `Web_Application`).
- **Required Tooling (`CASA 3.0 (AL1) Test Guide.md`):** `scripted harness`, `semgrep`.
- **Goal:** Add Semgrep AST rule `CASA3-WHK-02-weak-hmac-or-timing` in `casa-assessment/rules/casa3_al1_oauth.yml`, add structured `evaluate_whk02_signature_verification` in `casa-assessment/casa_audit/scanner.py` (preserving `evaluate_whk02_hmac_and_timing_safe` 4-tuple compatibility) using `_make_redacted_har_probe` across the 4 invalid-signature replay vectors (`absent`, `truncated`, `modified`, `foreign_key`) and `_run_oauth_semgrep_sarif`, emit `output/whk02-hmac-audit.json`, redacted `output/whk02-replayed.har`, `output/whk02-semgrep.sarif`, and `CASA3-WHK-02` SARIF 2.1.0 entries, and wire into `run_dynamic_and_protocol_checks`.

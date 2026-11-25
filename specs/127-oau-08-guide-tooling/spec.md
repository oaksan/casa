# Spec 127 — OAU-08 Guide-Compliant Tooling

- **Control:** `OAU-08` (57/61) — Access tokens are transmitted only in the `Authorization` header; never in query strings or URL fragments (`RFC 6750 §2.3; ASVS V3.1.1 (L1)`, Surface: `All`).
- **Required Tooling (`CASA 3.0 (AL1) Test Guide.md`):** `mitmproxy`, `Burp Suite`.
- **Goal:** Extract `evaluate_oau08_token_transport` in `casa-assessment/casa_audit/scanner.py` combining HTTP intercepting proxy log inspection via `_run_oauth_intercepting_proxy`, active resource query-token probes (`?access_token=`, `?token=`) via `_make_redacted_har_probe` (with query-parameter token redaction in HAR 1.2), Semgrep AST rule `CASA3-OAU-08-token-in-url-transport`, and client JS/TS/bundle inspection, emitting `output/oau08-transport-audit.json`, redacted `output/oau08-replayed.har`, `output/oau08-semgrep.sarif`, and `CASA3-OAU-08` SARIF 2.1.0 entries.

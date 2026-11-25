# Spec 123 — OAU-04 Guide-Compliant Tooling

- **Control:** `OAU-04` (53/61) — `state` and OIDC `nonce` are CSPRNG-generated, bound to the user agent session, and validated on return (`RFC 9700 §4.7; OIDC Core §3.1.2.1; CWE-352`).
- **Required Tooling (`CASA 3.0 (AL1) Test Guide.md`):** `mitmproxy`, `Burp Suite`, `SP 800-90B entropy estimator`.
- **Goal:** Extract `evaluate_oau04_state_nonce` reusing `_run_oauth_intercepting_proxy`, `_make_redacted_har_probe`, and `_run_oauth_semgrep_sarif`, performing SP 800-90B min-entropy (`>= 128` bits across 200 samples, 0 repeats), `state` (`omitted`, `replayed`, `modified`, `foreign_session`) + OIDC `nonce` (`omitted`, `foreign`) callback replay probes, Semgrep AST check (`CASA3-OAU-04-missing-state-or-weak-prng`), redacted `output/oau04-replayed.har`, `output/oau04-entropy-audit.json`, and `CASA3-OAU-04` SARIF 2.1.0 results.

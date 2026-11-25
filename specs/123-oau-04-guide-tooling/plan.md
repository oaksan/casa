# Plan 123 — OAU-04 Guide-Compliant Tooling

1. Add `CASA3-OAU-04-missing-state-or-weak-prng` to `casa-assessment/rules/casa3_al1_oauth.yml`.
2. Implement `evaluate_oau04_state_nonce` in `casa-assessment/casa_audit/scanner.py` immediately after `evaluate_oau03_redirect_uris`, reusing `_run_oauth_intercepting_proxy`, `_make_redacted_har_probe`, and `_run_oauth_semgrep_sarif`, plus SP 800-90B min-entropy estimation over 200 authorization samples and `state`/`nonce` callback replay probes.
3. Wire `OAU-04` in `run_dynamic_and_protocol_checks` using `evaluate_oau04_state_nonce`.
4. Add `test_iteration123_oau04_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering PASS (200 CSPRNG states >=128 bits + session-bound state/nonce rejection) and FAIL (low entropy / duplicate states, callback bypasses, missing OIDC nonce, Semgrep AST detection, and `[REDACTED]` HAR).
5. Document in `docs/justificativa2.txt`, run isolated + full unittest suite, execute live Juice Shop scan, commit, tag `sdd-123`, and push.

# Plan 130 — WHK-02 Guide-Compliant Tooling

1. Add `CASA3-WHK-02-weak-hmac-or-timing` to `casa-assessment/rules/casa3_al1_oauth.yml` targeting weak webhook HMAC algorithms (`sha1`/`md5`) and non-constant-time comparisons (`===`/`==`/`Buffer.compare`).
2. Add `evaluate_whk02_signature_verification` right after `evaluate_whk02_hmac_and_timing_safe` in `casa-assessment/casa_audit/scanner.py` reusing `_make_redacted_har_probe` and `_run_oauth_semgrep_sarif`, preserving the 4-tuple signature of `evaluate_whk02_hmac_and_timing_safe`.
3. Wire `evaluate_whk02_signature_verification` in `run_dynamic_and_protocol_checks` (`results["WHK-02"]`).
4. Add `test_iteration130_whk02_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering PASS (HMAC-SHA256 + `crypto.timingSafeEqual` + 401 denial across all 4 invalid-signature replays + `[REDACTED]` HAR + 0 Semgrep hits), FAIL (HMAC-SHA1 + `===` + HTTP 200 acceptance of invalid signatures + Semgrep hits + SARIF), and `Not_Covered` (no webhooks).
5. Document in `docs/justificativa2.txt`, run isolated + full `unittest` suite, execute live Juice Shop scan, commit, tag `sdd-130`, and push.

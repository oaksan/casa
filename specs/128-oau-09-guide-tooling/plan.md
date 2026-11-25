# Plan 128 — OAU-09 Guide-Compliant Tooling

1. Add `CASA3-OAU-09-jwt-validation-weakness` to `casa-assessment/rules/casa3_al1_oauth.yml`.
2. Extract `evaluate_oau09_token_validation` in `casa-assessment/casa_audit/scanner.py` right after `evaluate_oau08_token_transport`, reusing `_make_redacted_har_probe` and `_run_oauth_semgrep_sarif`.
3. Wire `evaluate_oau09_token_validation` in `run_dynamic_and_protocol_checks` (`results["OAU-09"]`).
4. Add `test_iteration128_oau09_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering PASS (endpoint accepts valid token and rejects all 7 crafted vectors + strict pinned verification) and FAIL (endpoint accepts `alg:none`, `HS256` pubkey confusion, expired `exp`, wrong `aud`/`iss`, insufficient `scope` + Semgrep `CASA3-OAU-09` + redacted HAR).
5. Document in `docs/justificativa2.txt`, run isolated + full `unittest` suite, execute live Juice Shop scan, commit, tag `sdd-128`, and push.

# Plan 127 — OAU-08 Guide-Compliant Tooling

1. Add `CASA3-OAU-08-token-in-url-transport` to `casa-assessment/rules/casa3_al1_oauth.yml`.
2. Extract `evaluate_oau08_token_transport` in `casa-assessment/casa_audit/scanner.py` right after `evaluate_oau07_token_storage`, reusing `_run_oauth_intercepting_proxy`, `_make_redacted_har_probe`, and `_run_oauth_semgrep_sarif`, plus URL token redaction in `output/oau08-replayed.har`.
3. Wire `evaluate_oau08_token_transport` in `run_dynamic_and_protocol_checks` (`results["OAU-08"]`).
4. Add `test_iteration127_oau08_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering PASS (`Authorization: Bearer`/`DPoP` over proxy + resource rejecting `?access_token=` with HTTP 401 + `[REDACTED]` HAR) and FAIL (`Authorization: Basic`, proxied `?access_token=` / JWT in fragment, backend accepting `?access_token=`, client `userinfo?access_token=` + Semgrep AST hits).
5. Document in `docs/justificativa2.txt`, run isolated + full `unittest` suite, execute live Juice Shop scan, commit, tag `sdd-127`, and push.

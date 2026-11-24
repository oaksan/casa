# Implementation Plan 122 — OAU-03 (`Intercepting Proxy URI Extractor` + `Callback Fuzzer`)

1. Extract `evaluate_oau03_redirect_uris(...)` in `casa-assessment/casa_audit/scanner.py` combining:
   - `_run_oauth_intercepting_proxy(...)` to capture flow `redirect_uri` parameters directly from proxied authorization traffic;
   - Multi-source `redirect_uri` collection (`/rest/admin/application-configuration`, HAR/crawl exchanges, `combined_oauth_sources`, `config/default.yml`);
   - Wildcard (`*`) and non-loopback `http:` URI validation;
   - Active `NoRedirect` callback/forwarding fuzzing over `redirect`, `next`, `continue`, `return_to`, `RelayState` (plus `to=` bypass vectors) using `_make_redacted_har_probe` & `_extract_redirect_target` (3xx `Location`, `meta-refresh`, `window.location`);
   - Evidence export to `output/oau03-redirect-audit.json`, redacted `output/oau03-replayed.har`, and `CASA3-OAU-03` SARIF 2.1.0 entries.
2. Wire `results["OAU-03"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration122_oau03_guide_tooling` in `casa-assessment/tests/test_iteration1.py`.
4. Append `CONTROLE 52/61: OAU-03 (Iteração SDD 122)` to `docs/justificativa2.txt`.
5. Run full `unittest` suite (`55` tests), verify live Juice Shop scan, commit, tag `sdd-122`, and push `main` + tags.

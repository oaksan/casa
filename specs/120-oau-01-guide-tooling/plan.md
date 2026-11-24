# Implementation Plan 120 — OAU-01 (`Intercepting Proxy` + `Semgrep OAuth Rules`)

1. Add dedicated ruleset `casa-assessment/rules/casa3_al1_oauth.yml` validated by `semgrep --validate`, detecting prohibited OAuth grants (`grant_type=password` / ROPC in HTTP clients/fetch/axios/requests/curl-like payloads and prohibited `response_type!=code` / Implicit fragment handling).
2. Add `evaluate_oau01_grant_type(...)` in `casa-assessment/casa_audit/scanner.py`:
   - Launches an ephemeral HTTP intercepting forward proxy (`_OAuthInterceptingProxy` on `127.0.0.1:0`) recording authorization (`response_type`) and token (`grant_type`, form/JSON body) requests into redacted HAR 1.2 (`output/oau01-replayed.har`, masking `Authorization`, `Cookie`, `Set-Cookie`, `password`, `client_secret`, `code`, `access_token`, `refresh_token`);
   - Drives authorization/flow requests via proxy (headless Chrome CDP `--proxy-server` or HTTP proxy tunnel when `auth_flow_url` / discovered OAuth authorize link or `oauth_flow_requests` are available);
   - Runs real **Semgrep** with `casa3_al1_oauth.yml` against `repo` and downloaded JS bundles (`--sarif`, exporting `output/oau01-semgrep.sarif`);
   - Parses `response_type` (rejecting anything other than exact `"code"`, including hybrids `"code id_token"`), `grant_type=password` ROPC, and Implicit fragment extraction (`#access_token=` / `parseRedirectUrlParams().access_token`);
   - Writes `output/oau01-grant-audit.json`, redacted `output/oau01-replayed.har`, and emits `CASA3-OAU-01` SARIF 2.1.0 entries.
3. Wire `results["OAU-01"]` inside `run_dynamic_and_protocol_checks`, preserving shared `oauth_bundle_texts` and `combined_oauth_sources` for `OAU-02`..`OAU-04`.
4. Add `test_iteration120_oau01_guide_tooling` in `casa-assessment/tests/test_iteration1.py` verifying PASS (`response_type=code` proxied authorization + `grant_type=authorization_code` token exchange + clean code -> `PASS`) and FAIL (hybrid `response_type=code token` proxied flow + real Semgrep detection of `grant_type=password` ROPC -> `FAIL`, with `[REDACTED]` HAR & SARIF verified).
5. Append `CONTROLE 50/61: OAU-01 (Iteração SDD 120)` to `docs/justificativa2.txt`.
6. Run full `unittest` suite (`53` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`), check off `tasks.md`, commit, tag `sdd-120`, and push `main` + tags.

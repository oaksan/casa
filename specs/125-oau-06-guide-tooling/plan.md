# Plan 125 — OAU-06 Guide-Compliant Tooling

1. Add `CASA3-OAU-06-embedded-client-secret` to `casa-assessment/rules/casa3_al1_oauth.yml`.
2. Update `evaluate_oau06_client_secret_scanner` to use `_extract_mobile_binary_text` on `.apk`/`.ipa`/`.crx`/`.xpi`/`.asar` and log redacted token-endpoint validation requests, keeping the 5-tuple return compatible.
3. Add `evaluate_oau06_client_secrets` right after `evaluate_oau05_system_browser` and wire it in `run_dynamic_and_protocol_checks` and `run_automated_al1_scan`.
4. Add `test_iteration125_oau06_guide_tooling` in `casa-assessment/tests/test_iteration1.py` (PASS on PKCE Kotlin + clean `.apk` ZIP + rejecting token endpoint; FAIL on compressed `.apk` + `.crx` extension containing `GOCSPX-` / `client_secret` accepted by `/oauth/token` + Semgrep + redacted HAR; `Not_Covered` on web-only repo).
5. Document in `docs/justificativa2.txt`, run isolated + full `unittest` suite, execute live Juice Shop scan, commit, tag `sdd-125`, and push.

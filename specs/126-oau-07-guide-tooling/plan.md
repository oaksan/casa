# Plan 126 — OAU-07 Guide-Compliant Tooling

1. Add `CASA3-OAU-07-insecure-token-storage` to `casa-assessment/rules/casa3_al1_oauth.yml` covering `localStorage.setItem`, `sessionStorage.setItem`, client JS `cookieService.put`, and mobile plaintext `SharedPreferences`/`UserDefaults`.
2. Extract `evaluate_oau07_token_storage` in `casa-assessment/casa_audit/scanner.py` right after `evaluate_oau06_client_secrets`, reusing headless browser storage dump, `_make_redacted_har_probe`, `_extract_mobile_binary_text`, and `_run_oauth_semgrep_sarif`, plus scanning `.xml`/`.plist` preference stores.
3. Wire `evaluate_oau07_token_storage` in `run_dynamic_and_protocol_checks` (`results["OAU-07"]`).
4. Add `test_iteration126_oau07_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering PASS (`HttpOnly; Secure` cookie, empty browser storage, EncryptedSharedPreferences/Keychain) and FAIL (`localStorage` snapshot / `nonHttpOnlyCookies` + missing `HttpOnly; Secure` `Set-Cookie` + plaintext Android `SharedPreferences`/zipped `.apk` + Semgrep AST + redacted HAR).
5. Document in `docs/justificativa2.txt`, run isolated + full `unittest` suite, execute live Juice Shop scan, commit, tag `sdd-126`, and push.

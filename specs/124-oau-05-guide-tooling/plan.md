# Plan 124 — OAU-05 Guide-Compliant Tooling

1. Add `CASA3-OAU-05-embedded-webview-oauth` to `casa-assessment/rules/casa3_al1_oauth.yml` for Kotlin/Java/Swift/TS/JS embedded WebView OAuth authorization detection.
2. Enhance `OAU-05` binary archive inspection (ZIP/APK/IPA `AndroidManifest.xml`, `Info.plist`, `classes*.dex`, `strings`) + keep `evaluate_oau05_system_browser_policy` 5-tuple signature compatible, and add structured `evaluate_oau05_system_browser` reusing `_run_oauth_intercepting_proxy` and `_run_oauth_semgrep_sarif`.
3. Wire `OAU-05` in `run_dynamic_and_protocol_checks` and `run_automated_al1_scan` (static Mobile/Native execution) to emit `output/oau05-browser-audit.json`, `output/oau05-replayed.har`, and `output/oau05-semgrep.sarif`.
4. Add `test_iteration124_oau05_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering PASS (CustomTabs/ASWebAuthenticationSession + clean APK ZIP), FAIL (Kotlin `WebView` + Swift `SFSafariViewController` + Semgrep AST + zipped `.apk` containing `WebView` + HAR embedded `; wv)` User-Agent via intercepting proxy), and `Not_Covered` (web-only repo forced in Mobile/Native scope).
5. Document in `docs/justificativa2.txt`, run isolated + full `unittest` suite, execute live Juice Shop scan, commit, tag `sdd-124`, and push.

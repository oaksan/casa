# Plan — SDD 062: OAU-05 Deep Automation

1. Extract `evaluate_oau05_system_browser_policy` in `casa-assessment/casa_audit/scanner.py` to scan client sources, binaries, live bundles, and HAR `User-Agent` headers.
2. Replace the static `OAU-05` stub in `run_dynamic_and_protocol_checks` with real `evaluate_oau05_system_browser_policy` invocation and `CASA3-OAU-05` SARIF emission, and execute statically inside `run_automated_al1_scan` whenever `Mobile`/`Native` surfaces are active without `target_url`.
3. Validate empirically against Juice Shop (`Web_Application` & `Mobile`/`Native`) and synthetic Android/iOS embedded-WebView vs system-browser fixtures.
4. Document Control 54/61 in `docs/justificativa.txt`, add unit test assertions in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-062`.

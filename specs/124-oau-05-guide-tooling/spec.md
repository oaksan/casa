# Spec 124 — OAU-05 Guide-Compliant Tooling

- **Control:** `OAU-05` (54/61) — Native, mobile and desktop clients perform authorization in the system browser (`Custom Tabs` / `ASWebAuthenticationSession`) — never an embedded WebView (`RFC 8252 §8.12`, Surface: `Mobile, Native`).
- **Required Tooling (`CASA 3.0 (AL1) Test Guide.md`):** `mitmproxy`, `MobSF`, `semgrep`.
- **Goal:** Upgrade `OAU-05` with ZIP/APK/IPA archive + `strings` MobSF-style extraction (`.apk`, `.ipa`, `.asar`), Semgrep multi-language rule `CASA3-OAU-05-embedded-webview-oauth` (`kotlin`, `java`, `swift`, `typescript`, `javascript`) via `_run_oauth_semgrep_sarif`, intercepting proxy User-Agent capture via `_run_oauth_intercepting_proxy`, structured `evaluate_oau05_system_browser` evaluator preserving backward-compatible `evaluate_oau05_system_browser_policy` 5-tuple, `output/oau05-browser-audit.json`, redacted `output/oau05-replayed.har`, `output/oau05-semgrep.sarif`, and `CASA3-OAU-05` SARIF 2.1.0 results.

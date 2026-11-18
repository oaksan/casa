# Specification — SDD 062: OAU-05 Deep Automation

- **Control ID:** `OAU-05`
- **Title:** Native, mobile and desktop clients perform authorization in the system browser (Custom Tabs / `ASWebAuthenticationSession`) — never an embedded WebView
- **External References:** RFC 8252 §8.12
- **Applicable Profile:** `Mobile`, `Native`

## Requirements
1. Scan client source files (`.kt`, `.java`, `.swift`, `.m`, `.mm`, `.cs`, `.dart`, `.ts`, `.js`), manifests (`AndroidManifest.xml`, `Info.plist`, `package.json`), client binaries (`.apk`, `.ipa`, `.asar`), live bundles, and HAR 1.2 `User-Agent` headers.
2. Flag in-app web views loading OAuth authorization flows (`WebView`, `WKWebView`, `UIWebView`, `SFSafariViewController`, `BrowserWindow`, `InAppBrowser`, `; wv)` User-Agent) with `CASA3-OAU-05` SARIF 2.1.0 findings.
3. Verify approved external system-browser authorization APIs (`CustomTabsIntent`, `ASWebAuthenticationSession`, `AppAuth`, `shell.openExternal`).
4. Respect surface scoping (`NOT_APPLICABLE` under `Web_Application`, honest `Not_Covered` when `Mobile`/`Native` surfaces are selected on a web-only workspace without mobile/native artifacts).

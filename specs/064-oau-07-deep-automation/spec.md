# Specification — SDD 064: OAU-07 Deep Automation

- **Control ID:** `OAU-07`
- **Title:** Access and refresh tokens are held in platform secure storage — Keystore, Keychain, or `HttpOnly Secure` cookie. Never `localStorage`, `SharedPreferences` plaintext, or disk cache
- **External References:** MASA 1.1.1.1 / 2.1.1.1; CWE-922; ASVS V6.4.1 (L2)
- **Applicable Profile:** `All`

## Requirements
1. Correlate live Headless Chrome CDP browser storage snapshots (`localStorage`, `sessionStorage`, `IndexedDB`, `document.cookie`) against active session/bearer tokens.
2. Audit HTTP `Set-Cookie` headers and client JS cookie writers (`cookieService.put`, `localStorage.setItem` including minified esbuild backtick strings in `main.js`) for missing `HttpOnly` / `Secure` flags, excluding `*.spec.ts` unit test noise.
3. Scan mobile sources for plaintext `SharedPreferences` / `NSUserDefaults` / `UserDefaults.standard` token storage lacking Keystore/Keychain APIs.
4. Emit `CASA3-OAU-07` findings to `output/dast-findings.sarif` (SARIF 2.1.0) and correlate redacted HAR 1.2 traffic.

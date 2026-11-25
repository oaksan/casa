# Spec 125 — OAU-06 Guide-Compliant Tooling

- **Control:** `OAU-06` (55/61) — No `client_secret` is embedded in a public client binary, bundle or extension package (`RFC 8252 §8.5; CWE-798`, Surface: `Mobile, Native`).
- **Required Tooling (`CASA 3.0 (AL1) Test Guide.md`):** `MobSF`, `apktool`, `strings`.
- **Goal:** Upgrade `OAU-06` to unpack `.apk`/`.ipa`/`.crx`/`.xpi`/`.asar` archives via shared `_extract_mobile_binary_text` (ZIP DEX/manifest/Plist + `strings`), detect hardcoded `client_secret`/provider tokens via Semgrep (`CASA3-OAU-06-embedded-client-secret`) + high-entropy adjacency, test extracted candidates against token endpoints with redacted HAR 1.2 logging via `evaluate_oau06_client_secrets`, emit `output/oau06-secret-audit.json`, redacted `output/oau06-replayed.har`, `output/oau06-semgrep.sarif`, and `CASA3-OAU-06` SARIF 2.1.0 while preserving `evaluate_oau06_client_secret_scanner` 5-tuple compatibility.

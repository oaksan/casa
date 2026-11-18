# Specification — SDD 063: OAU-06 Deep Automation

- **Control ID:** `OAU-06`
- **Title:** No client secret is embedded in a public client binary, bundle or extension package
- **External References:** RFC 8252 §8.5; CWE-798
- **Applicable Profile:** `Mobile`, `Native`

## Requirements
1. Extract strings, resources, and constant pools from mobile/native binaries (`.apk`, `.ipa`, `.asar`, `.crx`, `.xpi`), client source/resource files, and live served JS bundles.
2. Detect embedded client secrets via known issuer formats (`GOCSPX-...`, `gho_/ghu_/ghs_`), explicit `client_secret`/`clientSecret` key assignments, and high-entropy strings adjacent to `client_id`.
3. Present extracted candidates to loopback IdP `/oauth/token` endpoints when configured, inspect HAR 1.2 token exchanges for `client_secret`, and emit `CASA3-OAU-06` findings to SARIF 2.1.0.
4. Return accurate surface-scoped verdicts (`NOT_APPLICABLE` for `Web_Application`, `Not_Covered` for `Mobile`/`Native` workspaces without binaries/native sources, `FAIL`/`PASS` for real mobile/native packages).

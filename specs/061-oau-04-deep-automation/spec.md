# Specification — SDD 061: OAU-04 Deep Automation

- **Control ID:** `OAU-04`
- **Title:** `state` and OIDC `nonce` are CSPRNG-generated, bound to the user agent session, and validated on return
- **External References:** RFC 9700 §4.7; OIDC Core §3.1.2.1; CWE-352
- **Applicable Profile:** `All`

## Requirements
1. Probe live server-side OAuth authorization endpoints to collect up to 200 `state` values, enforce uniqueness, and verify per-character SP 800-90B min-entropy multiplied by value length `>= 128` bits.
2. Replay OAuth callbacks with `state` omitted, replayed, modified, and foreign-session via `http_probe` (recording in redacted HAR 1.2) and verify no authenticated session is issued.
3. Inspect live served JS bundles (`main.js`) and OAuth client components (`login.component.ts`, `oauth.component.ts`) for missing `state=`, non-CSPRNG generators (`Math.random()`), missing `nonce=` in OIDC `openid`/`id_token` requests, and missing session-bound `state` validation on callback return.
4. Emit `CASA3-OAU-04` findings in `output/dast-findings.sarif` (SARIF 2.1.0).

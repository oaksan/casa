# Feature Specification 120 — OAU-01 Guide-Compliant Tooling (`Intercepting Proxy Flow Capture` + `Semgrep OAuth Grant Rules` + `Bundle/Source Inspector`)

## Control Covered
- **ID:** `OAU-01`
- **Title:** Only the Authorization Code flow is used — Implicit and Resource Owner Password Credentials grants are prohibited
- **External Reference:** RFC 9700 §2.1.2, §2.4 (OAuth 2.0 Security BCP); RFC 6749 | **Profile:** `All`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Ephemeral **HTTP Intercepting Proxy (`127.0.0.1:0`)** with optional Headless Chrome CDP proxied IdP sign-in flow capture + **Semgrep (`1.180.0`)** static SARIF 2.1.0 OAuth grant-type rules (`casa3_al1_oauth.yml`) + live served JS bundle & source inspection, emitting OASIS SARIF 2.1.0 (`CASA3-OAU-01`, `output/oau01-semgrep.sarif`), structured JSON (`output/oau01-grant-audit.json`), and redacted HAR 1.2 (`output/oau01-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Every captured authorization request carries `response_type` strictly equal to `code`, zero token requests or scanned artifacts use `grant_type=password` (ROPC), and zero client artifacts consume Implicit fragment tokens (`#access_token=`).
  - **FAIL:** `response_type != code` (including `token`, `id_token`, or hybrid values like `code id_token`), or any `grant_type=password` ROPC token request / static finding.

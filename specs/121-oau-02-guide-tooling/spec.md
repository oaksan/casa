# Feature Specification 121 — OAU-02 Guide-Compliant Tooling (`Intercepting Proxy PKCE Flow & S256 Challenge Verifier` + `Semgrep OAU-02`)

## Control Covered
- **ID:** `OAU-02`
- **Title:** PKCE with `S256` is enforced on **all** authorization code flows, public and confidential
- **External Reference:** RFC 7636; RFC 9700 §2.1.1; MASA 1.3.1.1 / 2.3.1.1 | **Profile:** `All`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Shared HTTP **Intercepting Proxy (`_run_oauth_intercepting_proxy`)** capturing authorization & token requests into redacted HAR 1.2 + cryptographic **RFC 7636 `S256` verifier (`SHA-256(code_verifier) == code_challenge`)** + **Semgrep (`1.180.0`)** static SARIF 2.1.0 PKCE rule (`CASA3-OAU-02-*`) + live served JS bundle & source inspection, emitting OASIS SARIF 2.1.0 (`CASA3-OAU-02`, `output/oau02-semgrep.sarif`), structured JSON (`output/oau02-pkce-audit.json`), and redacted HAR 1.2 (`output/oau02-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Every captured authorization request carries `code_challenge_method=S256` and `code_challenge >= 43` characters, token exchange includes matching `code_verifier`, server rejects verifier-less token exchanges, and zero Semgrep/bundle PKCE violations appear.
  - **FAIL:** `code_challenge` absent or `< 43` chars, `code_challenge_method != S256` (e.g., `plain`), mismatched/missing `code_verifier`, or token exchange succeeding without valid `code_verifier`.

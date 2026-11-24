# Feature Specification 122 — OAU-03 Guide-Compliant Tooling (`Intercepting Proxy URI Capture` + `Callback/Forwarding Fuzzer`)

## Control Covered
- **ID:** `OAU-03`
- **Title:** Exact, non-wildcard redirect URIs and callback open-redirect/forwarding defense
- **External Reference:** RFC 9700 §2.1; CWE-601 | **Profile:** `All`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Shared **HTTP Intercepting Proxy (`_run_oauth_intercepting_proxy`)** capturing registered `redirect_uri` values + active `NoRedirect` callback/forwarding fuzzer across `redirect`, `next`, `continue`, `return_to`, `RelayState` (plus `to=` bypasses), emitting OASIS SARIF 2.1.0 (`CASA3-OAU-03`), structured JSON (`output/oau03-redirect-audit.json`), and redacted HAR 1.2 (`output/oau03-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Zero wildcard (`*`) redirect URIs, zero disallowed non-loopback `http:` redirect URIs, and zero 3xx `Location`, meta-refresh, or JS redirects to hosts outside the observed redirect URI host allowlist.
  - **FAIL:** `>= 1` wildcard URI, non-loopback `http:` redirect URI, or external off-allowlist callback redirect.

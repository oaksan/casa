# SDD Iteration 059 Spec: OAU-02 Deep Automation

## Control Under Audit
- **ID:** `OAU-02`
- **Requirement:** PKCE with `S256` is enforced on all authorization code flows, public and confidential (`RFC 7636; RFC 9700 §2.1.1`)
- **Surface:** `All`

## Gaps Identified
1. Scanner only checked `"code_challenge" in login_txt`, missing runtime JS bundles (`main.js`), `code_challenge_method=S256` enforcement (`plain` rejection), `>= 43` character length validation, `code_verifier` checks, and SARIF 2.1.0 reporting.

## Requirements
- Inspect both live served JS bundles (`main.js`) and client source files (`combined_oauth_sources`) extracting `?client_id=...&redirect_uri=...` authorization request URLs.
- Require `code_challenge`, `code_challenge_method=S256` (rejecting `plain`), `>= 43` chars on static challenges, and `code_verifier`, emitting `CASA3-OAU-02` into `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

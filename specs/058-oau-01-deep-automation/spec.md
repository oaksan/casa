# SDD Iteration 058 Spec: OAU-01 Deep Automation

## Control Under Audit
- **ID:** `OAU-01`
- **Requirement:** Only the Authorization Code flow is used — Implicit and Resource Owner Password Credentials grants are prohibited (`RFC 9700 §2.1.2, §2.4; RFC 6749`)
- **Surface:** `All`

## Gaps Identified
1. Scanner only checked `login.component.ts` locally without downloading/inspecting live served JS client bundles (`main.js`), `oauth.component.ts`, `user.service.ts`, or `grant_type=password` (ROPC).
2. Missing `CASA3-OAU-01` SARIF 2.1.0 entries and redacted HAR 1.2 artifact links.

## Requirements
- Fetch served `<script src="*.js">` bundles dynamically (`main.js`, `scripts.js`) alongside OAuth client source files (`login.component.ts`, `oauth.component.ts`, `user.service.ts`).
- Enforce `response_type == "code"`, detect `grant_type=password` (ROPC), and flag client-side implicit `#access_token=` handling.
- Emit `CASA3-OAU-01` findings to `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

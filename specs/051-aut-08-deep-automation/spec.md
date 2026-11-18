# SDD Iteration 051 Spec: AUT-08 Deep Automation

## Control Under Audit
- **ID:** `AUT-08`
- **Requirement:** Client-side storage holds no sensitive data or authentication material, and is cleared on logout (`OWASP ASVS V8.2.3 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner relied exclusively on static `localStorage.setItem` grep inside `frontend/src` without running a real headless browser.
2. Never dumped `sessionStorage`, `IndexedDB`, or `nonHttpOnlyCookies` before and after logout, nor checked canary values or Luhn-valid PANs.
3. Missing `CASA3-AUT-08` SARIF 2.1.0 entries and redacted artifact links.

## Requirements
- Launch headless Chrome (`--headless=new` via `casa-assessment/scripts/headless_storage_dump.js`), authenticate with a canary account via `/#/login`, dump `localStorage`, `sessionStorage`, `IndexedDB`, and `document.cookie` pre-logout, trigger UI logout (`#navbarLogoutButton`), and re-dump post-logout.
- Match stored values against JWT regex, observed session tokens, canary account fields, auth keys, and Luhn-valid PANs.
- Emit masked `CASA3-AUT-08` findings to `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

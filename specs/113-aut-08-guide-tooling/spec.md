# Feature Specification 113 — AUT-08 Guide-Compliant Tooling (`Headless Chrome CDP Storage Dump Harness`)

## Control Covered
- **ID:** `AUT-08`
- **Title:** Client-side storage holds no sensitive data or authentication material, and is cleared on logout
- **External Reference:** ASVS V8.2.3 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Headless browser (`google-chrome --headless=new` via CDP `scripts/headless_storage_dump.js`, Playwright-equivalent) dumping `localStorage`, `sessionStorage`, `IndexedDB` (databases and object stores), and non-`HttpOnly` `document.cookie` before and after logout, matching against observed session/access/refresh tokens, JWT regex, Luhn-valid PANs, seeded account canaries, and identity-provider profile values, outputting SARIF 2.1.0 (`CASA3-AUT-08`), redacted JSON dump (`output/aut08-storage-dump.json`), and redacted HAR 1.2 (`output/aut08-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** No stored item matches an observed token, JWT, Luhn-valid PAN, seeded canary value, or identity-provider profile field, **and** zero authentication/authorization material persists after logout.
  - **FAIL:** `>= 1` sensitive/canary/JWT/PAN item is stored in client-side storage OR `>= 1` item of authentication material survives logout.

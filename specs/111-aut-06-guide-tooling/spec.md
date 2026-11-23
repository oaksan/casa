# Feature Specification 111 — AUT-06 Guide-Compliant Tooling (`OWASP ZAP 10010/10011/10054` + `Set-Cookie Attribute Inspector`)

## Control Covered
- **ID:** `AUT-06`
- **Title:** Session cookies set `Secure`, `HttpOnly` and `SameSite` (`Lax` or `Strict`)
- **External Reference:** ASVS V3.4.1, V3.4.2, V3.4.3 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** **OWASP ZAP** (Passive rules `10010` Cookie No HttpOnly Flag, `10011` Cookie Without Secure Flag, `10054` Cookie without SameSite Attribute) + authenticated crawl `Set-Cookie` inspector + cookie-removal session-dependency verification + client-side JS cookie creation audit, outputting SARIF 2.1.0 (`CASA3-AUT-06`) and redacted HAR 1.2 (`output/aut06-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Every `Set-Cookie` header setting a session cookie carries `Secure`, `HttpOnly`, and `SameSite=Lax` or `SameSite=Strict`, with zero ZAP cookie attribute violations on session cookies.
  - **FAIL:** `>= 1` session cookie is missing `Secure`, `HttpOnly`, or `SameSite=Lax|Strict`, or session tokens are written to cookies client-side via JS (`cookieService.put` / `document.cookie`) without server `HttpOnly`.

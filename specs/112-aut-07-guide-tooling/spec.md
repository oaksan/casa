# Feature Specification 112 — AUT-07 Guide-Compliant Tooling (`PyJWT` + `jwt_tool`-Equivalent Forged-Token Harness)

## Control Covered
- **ID:** `AUT-07`
- **Title:** Stateless tokens are signed with a strong algorithm; `alg:none`, algorithm confusion and key substitution rejected; non-revocable tokens expire ≤ 24 hours
- **External Reference:** ASVS V3.5.3 (L2); RFC 8725 (JWT BCP); CWE-347 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Forged-JWT harness equivalent to `jwt_tool` backed by **PyJWT (`2.10.1`)** inspecting genuine token header/claims (`alg`, `iat`, `exp`), verifying `HS256` secret bit-length when source is present (recording `Not_Covered` otherwise), submitting crafted attack vectors (`alg:none`, `RS256->HS256` key confusion, foreign `kid`, injected `jku`, modified payload with original signature) to protected routes, outputting SARIF 2.1.0 (`CASA3-AUT-07`), JSON audit report (`output/aut07-jwt-audit.json`), and redacted HAR 1.2 (`output/aut07-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Every crafted token is denied; signing algorithm is in `{RS256, RS384, RS512, ES256, ES384, PS256, EdDSA, HS256}` (for `HS256`, key length `>= 256` bits where available, else `Not_Covered`); and every non-revocable token accepted after `AUT-05` logout carries `exp` with lifetime `<= 86400` seconds.
  - **FAIL:** Any crafted token accepted; algorithm outside allowlist; `HS256` key `< 256` bits; or token accepted after `AUT-05` logout omits `exp` or has lifetime `> 86400` seconds.

# Implementation Plan 112 — AUT-07 (`PyJWT` + Crafted-Token Harness)

1. Extract `evaluate_aut07_jwt_security(...)` in `casa-assessment/casa_audit/scanner.py` using `PyJWT` (`2.10.1`) + base64url inspection for token header/claims, public key/JWKS discovery (`/encryptionkeys/jwt.pub`, `/.well-known/jwks.json`, repo fallback), forged-token replay (`alg:none`, `HS256` key confusion, foreign `kid`, injected `jku`, modified payload), `HS256` key length check (`>= 256` bits or `Not_Covered`), post-`AUT-05` expiration check (`<= 86400s` from `iat` or observed issuance time), SARIF 2.1.0 (`CASA3-AUT-07`), JSON report (`output/aut07-jwt-audit.json`), and redacted HAR 1.2 (`output/aut07-replayed.har`).
2. Wire `results["AUT-07"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration112_aut07_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering:
   - **PASS:** Strong `HS256` (>= 256-bit secret) or `RS256` with `exp <= 86400s` rejecting all crafted tokens (`Not_Covered` key length documented when source omitted + `[REDACTED]` HAR verified);
   - **FAIL (`alg:none` + key confusion):** Server accepts unsigned `alg:none` or `HS256` public-key confusion tokens -> `FAIL`;
   - **FAIL (`AUT-05` non-revocable lifetime > 86400s or missing `exp` / weak `HS256` key `< 256` bits):** -> `FAIL` (`CASA3-AUT-07`).
4. Append `CONTROLE 42/61: AUT-07 (Iteração SDD 112)` to `docs/justificativa2.txt`.
5. Run full `unittest` suite (`45` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`) with refreshed `casa_audit` daemon, check off `tasks.md`, commit, tag `sdd-112`, and push `main` + tags.

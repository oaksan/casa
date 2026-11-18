# SDD Iteration 050 Spec: AUT-07 Deep Automation

## Control Under Audit
- **ID:** `AUT-07`
- **Requirement:** Stateless tokens are signed with a strong algorithm; `alg:none`, algorithm confusion and key substitution rejected; non-revocable tokens expire <= 24 hours (`OWASP ASVS V3.5.3 (L2); RFC 8725; CWE-347`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner relied strictly on a single static pattern in `lib/insecurity.ts` without submitting crafted JWTs dynamically.
2. Never tested `alg:none`, live `HS256` public-key confusion, `kid` injection, `jku` injection, tampered payload, signing algorithm allowlist, HS256 >= 256-bit key check, or post-AUT-05 `exp <= 86400s` lifetime validation.
3. Missing `CASA3-AUT-07` SARIF 2.1.0 entries in `output/dast-findings.sarif`.

## Requirements
- Decode genuine JWT headers/claims (`alg`, `iat`, `exp`), verify allowlist membership and HS256 key bit length when present, and enforce `exp` presence with lifetime `<= 86400s` when tokens survive `AUT-05` logout replay.
- Construct and submit all 5 forged JWT vectors (`alg:none`, `HS256` with fetched public key, foreign `kid`, injected `jku`, modified payload) against `/rest/wallet/balance`.
- Emit `CASA3-AUT-07` findings into `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

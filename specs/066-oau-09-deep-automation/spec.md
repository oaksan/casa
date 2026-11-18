# Specification — SDD 066: OAU-09 Deep Automation

- **Control ID:** `OAU-09`
- **Title:** Where the application's own backend accepts identity-provider ID tokens or access tokens as proof of identity, it validates signature, `iss`, `aud`, `exp` and `scope` against the identity provider's published keys; `alg:none` and algorithm confusion are rejected
- **External References:** RFC 9700 §4.9; RFC 8725; CWE-347
- **Applicable Profile:** `Web_Application`

## Requirements
1. Confirm baseline acceptance of a legitimate Bearer token at protected resource endpoints (`/rest/wallet/balance`, `/rest/basket/{bid}`).
2. Construct and actively replay 7 crafted token vectors against each token-accepting endpoint:
   - `unsigned_alg_none` (`alg:none`)
   - `foreign_signing_key` (untrusted HS256 secret)
   - `alg_confusion_hs256_pubkey` (`RS256` -> `HS256` signed with exposed public key)
   - `expired_exp_claim` (`exp=1577836800`)
   - `wrong_audience_aud` (`aud="https://wrong-audience.example.com"`)
   - `wrong_issuer_iss` (`iss="https://wrong-issuer.example.com"`)
   - `insufficient_scope` (`scope="minimal:none"`)
3. Record all HTTP replay probes in redacted HAR 1.2 (`output/dast-capture.har`) and emit per-endpoint `CASA3-OAU-09` findings into `output/dast-findings.sarif` (SARIF 2.1.0).

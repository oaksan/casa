# Implementation Plan — Iteration 050 (`AUT-07`)

1. Import `base64`, `hashlib`, and `hmac` in `casa-assessment/casa_audit/scanner.py`.
2. Replace the static `lib/insecurity.ts` check for `AUT-07` with active decoding of `alg`/`iat`/`exp` (verifying `exp` <= 86400s when accepted post-AUT-05), fetching `/encryptionkeys/jwt.pub`, and submitting 5 crafted JWT attack vectors against `/rest/wallet/balance`.
3. Preserve `jwt_confusion` for downstream `OAU-09` and emit `CASA3-AUT-07` results into `dast_sarif_results` (`output/dast-findings.sarif`).
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`).
5. Update `docs/justificativa.txt` and `casa-assessment/tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-050`, and push.

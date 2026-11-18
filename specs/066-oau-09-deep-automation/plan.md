# Plan — SDD 066: OAU-09 Deep Automation

1. Replace the static `jwt_confusion` alias in `OAU-09` inside `casa-assessment/casa_audit/scanner.py` with an active 7-vector crafted token replay harness targeting `/rest/wallet/balance` and `/rest/basket/{bid}`.
2. Distinguish rejected vectors (`expired_exp_claim`, `foreign_signing_key` -> HTTP 401) from accepted bypass vectors (`unsigned_alg_none`, `alg_confusion_hs256_pubkey`, `wrong_audience_aud`, `wrong_issuer_iss`, `insufficient_scope` -> HTTP 200).
3. Emit `CASA3-OAU-09` SARIF 2.1.0 results and validate empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Document Control 58/61 in `docs/justificativa.txt`, assert in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-066`.

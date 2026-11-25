# Spec 128 — OAU-09 Guide-Compliant Tooling

- **Control:** `OAU-09` (58/61, closes Domain 7) — Backend token signature, `iss`, `aud`, `exp`, `scope`, `alg:none`, and algorithm-confusion validation (`RFC 9700 §4.9; RFC 8725; CWE-347`, Surface: `Web_Application`).
- **Required Tooling (`CASA 3.0 (AL1) Test Guide.md`):** `jwt_tool`, `scripted harness`.
- **Goal:** Extract `evaluate_oau09_token_validation` in `casa-assessment/casa_audit/scanner.py` executing the 7-vector forged JWT replay harness (`unsigned_alg_none`, `foreign_signing_key`, `alg_confusion_hs256_pubkey`, `expired_exp_claim`, `wrong_audience_aud`, `wrong_issuer_iss`, `insufficient_scope`) via `_make_redacted_har_probe` against every token-accepting endpoint + JWKS/public-key resolution + Semgrep AST rule `CASA3-OAU-09-jwt-validation-weakness`, emitting `output/oau09-token-audit.json`, redacted `output/oau09-replayed.har`, `output/oau09-semgrep.sarif`, and `CASA3-OAU-09` SARIF 2.1.0 entries.

# Plano — SDD 191 (WHK-02)

1. Atualizar `evaluate_whk02_hmac_and_timing_safe` em `casa-assessment/casa_audit/scanner.py` e `CASA3-WHK-02-weak-hmac-or-timing` em `casa-assessment/rules/casa3_al1_oauth.yml`:
   - Adicionar cabeçalhos `webhook-id`, `webhook-timestamp` e `webhook-signature` (Standard Webhooks `v1,...`) aos vetores `truncated_signature`, `modified_signature` e `foreign_key_signature`.
   - Reconhecer `hash_equals`, `secure_compare`, `fixed_length_secure_compare` e `FixedTimeEquals` como comparações constant-time válidas.
   - Tratar HTTP 2xx com envelope JSON de negação (`_is_json_denial`) como rejeitado (Guia L25).
2. Validar YAML com `semgrep --validate`, adicionar `test_iteration191_whk02_neon_reeval`, validar regressão `test_iteration130_whk02_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar, criar tag `sdd-191` e fazer push.

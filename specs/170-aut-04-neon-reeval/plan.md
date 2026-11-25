# Plano Técnico — SDD 170 (AUT-04)

1. Atualizar `evaluate_aut04_url_token_leak` em `casa-assessment/casa_audit/scanner.py`:
   - Expandir `_redact_url_str` e `sens_param_re` com `api_key`, `apikey`, `auth_token`, `bearer`, `client_secret`, `code_verifier` e `secret`.
   - Aplicar `urllib.parse.unquote` antes de verificar `tok_set` e `jwt_url_re` em URLs, cabeçalhos `Referer` e cabeçalhos `Location`/`Refresh`.
2. Adicionar teste unitário `test_iteration170_aut04_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-170` e fazer push.

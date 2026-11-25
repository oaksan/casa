# Plano — SDD 187 (OAU-07)

1. Atualizar `evaluate_oau07_token_storage` em `casa-assessment/casa_audit/scanner.py`:
   - Inspecionar o conteúdo serializado de entradas `indexedDB` para detectar `observed_token` ou padrões JWT mesmo sob nome de banco benigno.
   - Separar múltiplos `Set-Cookie` via `_split_set_cookie_headers`, ignorando deleções (`Max-Age=0` ou valor vazio), e auditar cada cookie de token/sessão individualmente.
2. Criar `test_iteration187_oau07_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar regressão `test_iteration126_oau07_guide_tooling`, commitar, criar tag `sdd-187` e fazer push.

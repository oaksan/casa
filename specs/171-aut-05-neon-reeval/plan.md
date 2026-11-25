# Plano Técnico — SDD 171 (AUT-05)

1. Atualizar `evaluate_aut05_logout_invalidation` em `casa-assessment/casa_audit/scanner.py`:
   - Incluir `("POST", "/logout")` e `("DELETE", "/api/session")` nos `logout_endpoints` padrão.
   - Reconhecer payloads JSON explícitos de negação (Guia L25) no replay pós-logout.
   - Enviar fallback `application/x-www-form-urlencoded` (`grant_type=refresh_token&refresh_token=...`) no replay de refresh tokens caso o POST JSON retorne 400/415.
2. Adicionar teste unitário `test_iteration171_aut05_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-171` e fazer push.

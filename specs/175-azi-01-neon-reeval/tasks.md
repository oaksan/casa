# Tarefas — SDD 175 (AZI-01)

- [x] Auditar `AZI-01` contra `CASA 3.0 (AL1) Test Guide.md` (linhas 965–983, confirmando 0 Burp Suite pago)
- [x] Restringir verificação `SameSite=None` a cookies de sessão e adicionar `cookie_name`/`state_field` em `evaluate_azi01_anti_csrf`
- [x] Adicionar teste unitário `test_iteration175_azi01_neon_reeval` e documentar em `docs/justificativaNeon.txt`
- [x] Validar testes unitários + regressão, commitar, taggear `sdd-175` e fazer push

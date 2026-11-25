# Plano Técnico — SDD 175 (AZI-01)

1. Atualizar `evaluate_azi01_anti_csrf` em `casa-assessment/casa_audit/scanner.py`:
   - Adicionar parâmetros opcionais `cookie_name: str = "token"` e `state_field: str = "username"`.
   - Inspecionar `Set-Cookie` por cookie individual usando `_split_set_cookie_headers` + `_inspect_cookie_flags`, sinalizando `samesite_none_cookie` exclusivamente em cookies de sessão.
2. Adicionar teste unitário `test_iteration175_azi01_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-175` e fazer push.

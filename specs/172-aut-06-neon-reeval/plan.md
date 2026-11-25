# Plano Técnico — SDD 172 (AUT-06)

1. Atualizar `_inspect_cookie_flags` e `evaluate_aut06_session_cookie_flags` em `casa-assessment/casa_audit/scanner.py`:
   - Retornar `value` e `isDeletion` (`max-age=0` ou valor vazio) em `_inspect_cookie_flags`.
   - Adicionar parâmetros opcionais `protected_endpoint` e `session_cookie_names` em `evaluate_aut06_session_cookie_flags` e implementar ablação comportamental de cookies contra `protected_endpoint`.
2. Adicionar teste unitário `test_iteration172_aut06_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-172` e fazer push.

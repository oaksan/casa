# Plano Técnico — SDD 165 (CFG-10)

1. Atualizar `evaluate_cfg10_admin_reachability` em `casa-assessment/casa_audit/scanner.py` para:
   - Aceitar parâmetros opcionais `auth_routes` e `admin_wordlist`.
   - Calcular similaridade LCS máxima entre texto bruto e texto com timestamps ISO-8601/UUIDs normalizados.
   - Detectar exposição administrativa em modo sem `auth_headers` quando o corpo não é SPA fallback, não é trivial e não é formulário de login (`type="password"`).
2. Adicionar teste unitário `test_iteration165_cfg10_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-165` e fazer push.

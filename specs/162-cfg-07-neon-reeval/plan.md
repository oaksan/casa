# Plano Técnico — SDD 162 (CFG-07)

1. Atualizar `evaluate_cfg07_anti_caching` em `casa-assessment/casa_audit/scanner.py` para:
   - Aceitar `auth_headers` e `endpoints` opcionais (pulando o login padrão quando `auth_headers` já for fornecido).
   - Rejeitar combinação contraditória `public` + `no-store` em `Cache-Control`.
2. Adicionar teste unitário `test_iteration162_cfg07_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar auditoria em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-162` e fazer push.

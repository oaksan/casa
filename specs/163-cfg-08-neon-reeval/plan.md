# Plano Técnico — SDD 163 (CFG-08)

1. Atualizar `evaluate_cfg08_cors` em `casa-assessment/casa_audit/scanner.py` para incluir `prefix_matching_origin` (`https://{host}.evil.example.com`), retornar `prefixOrigin` e aceitar `endpoints` opcional.
2. Adicionar teste unitário `test_iteration163_cfg08_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Registrar justificativa em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-163` e fazer push.

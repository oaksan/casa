# Plano Técnico — SDD 161 (CFG-06)

1. Atualizar `evaluate_cfg06_xcto` em `casa-assessment/casa_audit/scanner.py` para aceitar `extra_endpoints: list[str] | None = None` e incluir `/nonexistent-cfg06-probe` nas sondas padrão standalone (garantindo verificação em respostas de erro 4xx).
2. Adicionar teste unitário `test_iteration161_cfg06_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar auditoria em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-161` e fazer push.

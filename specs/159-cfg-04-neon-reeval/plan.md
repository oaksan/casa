# Plano Técnico — SDD 159 (CFG-04)

1. Atualizar `evaluate_cfg04_csp` em `casa-assessment/casa_audit/scanner.py` para:
   - Rejeitar diretiva efetiva vazia (`not dirs[eff_source_name]`).
   - Inspecionar também `script-src-elem` e `script-src-attr` (quando presentes na política CSP3) contra tokens proibidos e achados do `csp-evaluator`.
2. Adicionar teste unitário `test_iteration159_cfg04_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Registrar justificativa em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-159` e enviar ao remoto.

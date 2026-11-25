# Plano Técnico — SDD 157 (CFG-02)

1. Atualizar `evaluate_cfg02_debug_modes` em `casa-assessment/casa_audit/scanner.py` para aceitar `crawled_exchanges` (e opcional `nuclei_result`) e varrer corpos de respostas rastreadas por assinaturas de debug de frameworks (Django, Werkzeug/Flask, Rails, ASP.NET, Laravel Whoops).
2. Passar `crawled_exchanges=crawled_exchanges` na chamada de `evaluate_cfg02_debug_modes` dentro de `run_dynamic_and_protocol_checks`.
3. Adicionar teste unitário `test_iteration157_cfg02_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
4. Registrar justificativa em `docs/justificativaNeon.txt`, rodar testes unitários + regressão, commitar, taggear `sdd-157` e fazer push.

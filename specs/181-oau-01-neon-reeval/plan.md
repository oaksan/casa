# Plano — SDD 181 (OAU-01)

1. Corrigir regex `response_type` e `grant_type` em `evaluate_oau01_grant_type` (`casa-assessment/casa_audit/scanner.py`) para capturar fluxos híbridos com espaço literal (`code id_token`) e configurações em objetos JSON/JS (`responseType`, `grantType`).
2. Adicionar `test_iteration181_oau01_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Registrar em `docs/justificativaNeon.txt`, executar novo teste + regressão `test_iteration120_oau01_guide_tooling`, commitar, criar tag `sdd-181` e fazer push.

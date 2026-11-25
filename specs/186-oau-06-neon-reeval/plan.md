# Plano — SDD 186 (OAU-06)

1. Expandir a inspeção de HAR em `evaluate_oau06_client_secret_scanner` (`casa-assessment/casa_audit/scanner.py`) para detectar `client_secret` em `request.postData.text` e `Authorization: Basic` em requisições para `/token`.
2. Criar `test_iteration186_oau06_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar regressão `test_iteration125_oau06_guide_tooling`, commitar, criar tag `sdd-186` e fazer push.

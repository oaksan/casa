# Plano — SDD 190 (WHK-01)

1. Atualizar `evaluate_whk01_delivery_tls` e `_whk01_tls_matrix` em `casa-assessment/casa_audit/scanner.py`:
   - Incluir `SSLv2` e `SSLv3` em `legacy_w` e normalizar nomes de protocolo retornados por `testssl.sh`.
   - Validar `p_loc.scheme == "https" and p_loc.hostname` em respostas 3xx de probes HTTP em claro.
2. Criar `test_iteration190_whk01_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, rodar novo teste + regressão `test_iteration129_whk01_guide_tooling`, commitar, criar tag `sdd-190` e fazer push.

# Plano — SDD 188 (OAU-08)

1. Atualizar `evaluate_oau08_token_transport` em `casa-assessment/casa_audit/scanner.py` para detectar `HAR_Fragment_Access_Token` e `HAR_Body_Form_Access_Token`, e redigir tokens em `postData.text` no HAR 1.2 de saída.
2. Criar `test_iteration188_oau08_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py` validando detecção de fragmento opaco, corpo POST form-encoded e PASS para `Authorization: DPoP ...`.
3. Documentar em `docs/justificativaNeon.txt`, validar regressão `test_iteration127_oau08_guide_tooling`, commitar, criar tag `sdd-188` e fazer push.

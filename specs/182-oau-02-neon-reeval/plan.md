# Plano — SDD 182 (OAU-02)

1. Endurecer `evaluate_oau02_pkce` em `casa-assessment/casa_audit/scanner.py` para validar limites superiores (`<= 128`) e conjunto de caracteres RFC 7636 de `code_challenge` e `code_verifier`.
2. Adicionar `test_iteration182_oau02_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py` validando rejeição de `code_verifier` curto (`< 43`) e `code_challenge` com padding/caracteres inválidos, e aprovação para par S256 válido.
3. Registrar em `docs/justificativaNeon.txt`, rodar novo teste + regressão `test_iteration121_oau02_guide_tooling`, commitar, criar tag `sdd-182` e fazer push.

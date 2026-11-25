# Plano Técnico — SDD 173 (AUT-07)

1. Atualizar `evaluate_aut07_jwt_security` em `casa-assessment/casa_audit/scanner.py`:
   - Adicionar vetor `unsigned_alg_none_mixedcase` (`{"alg": "None", "typ": "JWT"}`).
   - Adicionar vetor `embedded_jwk_key_substitution` com chave EC P-256 efêmera embutida em `header.jwk` e assinatura ES256 válida para essa chave do atacante.
   - Expandir regex de extração de segredo HS256 em código-fonte para incluir `jwt.sign(..., "<literal>")`.
2. Adicionar teste unitário `test_iteration173_aut07_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-173` e fazer push.

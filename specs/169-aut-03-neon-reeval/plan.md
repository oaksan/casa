# Plano Técnico — SDD 169 (AUT-03)

1. Atualizar `evaluate_aut03_session_fixation` em `casa-assessment/casa_audit/scanner.py`:
   - Incluir `PHPSESSID` e `ASP.NET_SessionId` em `fixation_cookie_pairs` e no cabeçalho `Cookie` de replay.
   - Aceitar respostas `302`/`303` de login ao extrair o identificador pós-autenticação de `Set-Cookie`.
2. Adicionar teste unitário `test_iteration169_aut03_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-169` e fazer push.

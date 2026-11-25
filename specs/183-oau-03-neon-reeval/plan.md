# Plano — SDD 183 (OAU-03)

1. Adicionar parâmetro opcional `surfaces: list[str] | None = None` em `evaluate_oau03_redirect_uris` para sinalizar `Web_Surface_Loopback_HTTP_Redirect_URI` quando `http://localhost` for registrado em superfície exclusivamente `Web_Application`.
2. Atualizar `_inspect_cb` para usar `_parse_redirect_scheme_host` (normalização `/\`, `\\` e detecção de `javascript:`/`data:`).
3. Criar `test_iteration183_oau03_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
4. Documentar em `docs/justificativaNeon.txt`, validar regressão `test_iteration122_oau03_guide_tooling`, commitar, criar tag `sdd-183` e fazer push.

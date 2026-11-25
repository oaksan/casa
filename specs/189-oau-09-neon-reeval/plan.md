# Plano — SDD 189 (OAU-09 + Fechamento Domínio 7)

1. Atualizar `evaluate_oau09_token_validation` em `casa-assessment/casa_audit/scanner.py` para incluir `unsigned_alg_none_mixedcase` (`alg: None`), `nbf_future_claim` (RFC 7519 §4.1.5) e filtro `_is_json_denial(v9_body)` (Guia L25).
2. Adicionar `test_iteration189_oau09_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Executar `test_iteration189_oau09_neon_reeval` + suíte completa `unittest discover` (122 testes `OK`) + reiniciar daemon `casa_audit` e executar scan ao vivo completo contra OWASP Juice Shop.
4. Registrar fechamento do Domínio 7 em `docs/justificativaNeon.txt`, commitar, criar tag `sdd-189` e fazer push.

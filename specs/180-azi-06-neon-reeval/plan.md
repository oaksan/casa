# Plano — SDD 180 (AZI-06 + Fechamento Domínio 6)

1. Adicionar `_parse_redirect_scheme_host` em `casa-assessment/casa_audit/scanner.py` para normalizar `/\`, `\\` e `scheme:\` conforme browsers modernos, além de sinalizar esquemas `javascript:` e `data:`.
2. Atualizar `_extract_redirect_target` para suportar aspas no atributo `url=` de meta-refresh e incluir vetor `backslash_bypass` em `redir_vectors`.
3. Adicionar `test_iteration180_azi06_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
4. Executar teste unitário + regressão `test_iteration119_azi06_guide_tooling`, seguido pela suíte completa (`unittest discover`, 113 testes) e scan ao vivo contra OWASP Juice Shop.
5. Registrar resultados e fechamento do Domínio 6 em `docs/justificativaNeon.txt`, commitar, criar tag `sdd-180` e fazer push.

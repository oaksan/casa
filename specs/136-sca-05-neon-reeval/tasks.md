# Tarefas — SDD 136 (`SCA-05`)

- [x] Auditar ferramentas e critérios de `SCA-05` contra `CASA 3.0 (AL1) Test Guide.md`
- [x] Corrigir `TOP_CANONICAL_NPM_PACKAGES`, adicionar cobertura PyPI (`TOP_CANONICAL_PYPI_PACKAGES` + `fetch_pypi_maintainers`) e dependências transitivas + fix do `break` prematuro
- [x] Adicionar `test_iteration136_sca05_neon_reeval` e validar contra `test_iteration75_sca05_guide_tooling`
- [x] Executar validação de fechamento do Domínio 1: suíte completa `unittest discover` (69/69 OK) + varredura ao vivo contra OWASP Juice Shop (`SCA-01..SCA-05`)
- [x] Documentar `CONTROLE 05/61: SCA-05 (Iteração SDD 136)` e consolidação do Domínio 1 em `docs/justificativaNeon.txt`
- [x] Commit, tag `sdd-136` e `git push origin main --tags`

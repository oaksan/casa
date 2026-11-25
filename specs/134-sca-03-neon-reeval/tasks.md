# Tarefas — SDD 134 (`SCA-03`)

- [x] Auditar ferramentas e critérios de `SCA-03` contra `CASA 3.0 (AL1) Test Guide.md`
- [x] Refinar `parse_trivy_os_report` para exigir mitigação documentada em `will_not_fix` e bloquear `end_of_life`
- [x] Remover lista hardcoded de pacotes Debian 13, suportar `trivy image` remoto e `docker-compose*.yml`, e retornar `Not_Covered` honesto quando imagem não puder ser obtida
- [x] Adicionar `test_iteration134_sca03_neon_reeval` e validar testes (`SDD 134` + `SDD 073`)
- [x] Documentar `CONTROLE 03/61: SCA-03 (Iteração SDD 134)` em `docs/justificativaNeon.txt`
- [x] Commit, tag `sdd-134` e `git push origin main --tags`

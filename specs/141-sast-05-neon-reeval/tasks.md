# Tarefas — SDD 141 (`SAST-05`)

- [x] Auditar ferramentas e critérios de `SAST-05` contra `CASA 3.0 (AL1) Test Guide.md`
- [x] Eliminar falso positivo em `this.setDataValue('password', ...)` para KDFs aprovados em `casa3_al1_sast.yml`
- [x] Exigir parâmetros explícitos (`type`, `memoryCost`, `timeCost`) e proveniência CSPRNG de `salt` explícito em `argon2.hash(...)`
- [x] Adicionar `test_iteration141_sast05_neon_reeval` e validar testes (`SDD 141` + `SDD 080`)
- [x] Documentar `CONTROLE 10/61: SAST-05 (Iteração SDD 141)` em `docs/justificativaNeon.txt`
- [x] Commit, tag `sdd-141` e `git push origin main --tags`

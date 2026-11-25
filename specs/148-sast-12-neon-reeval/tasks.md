# Tarefas — SDD 148 (`SAST-12`)

- [x] Auditar ferramentas e critérios de `SAST-12` contra `CASA 3.0 (AL1) Test Guide.md`
- [x] Substituir checagem hardcoded do Juice Shop por `trivy image --scanners secret` genérico em `evaluate_sast12_secrets_management_and_iac`
- [x] Adicionar detecção de runtime secret mounts (`/run/secrets/`, `secretKeyRef`, CSI) e ignorar `${VAR}` em `iac_secret_re`
- [x] Adicionar `test_iteration148_sast12_neon_reeval` e validar testes (`SDD 148` + `SDD 087`)
- [x] Documentar `CONTROLE 17/61: SAST-12 (Iteração SDD 148)` em `docs/justificativaNeon.txt`
- [x] Commit, tag `sdd-148` e `git push origin main --tags`

# Tarefas — SDD 149 (`SAST-13`)

- [x] Auditar ferramentas e critérios de `SAST-13` contra `CASA 3.0 (AL1) Test Guide.md`
- [x] Expandir fontes sensíveis JS/TS e adicionar regra taint PHP em `casa3_al1_sast.yml`
- [x] Evoluir `evaluate_sast13_canary_log_replay` (suporte `extra_log_paths`, logs na raiz, canário CVV e confirmação de hash irreversível)
- [x] Adicionar `test_iteration149_sast13_neon_reeval` e validar testes (`SDD 149` + `SDD 088`)
- [x] Executar validação de fechamento do Domínio 2: suíte completa `unittest discover` + fix ZAP passive-scan + varredura ao vivo contra OWASP Juice Shop (`SAST-01..SAST-13`)
- [x] Documentar `CONTROLE 18/61: SAST-13 (Iteração SDD 149)` e consolidação do Domínio 2 em `docs/justificativaNeon.txt`
- [x] Commit, tag `sdd-149` e `git push origin main --tags`

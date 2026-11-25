# Plano Técnico — SDD 134 (`SCA-03`)

1. Evoluir `parse_trivy_os_report(trivy_data, documented_mitigations=None)` mantendo compatibilidade retroativa com `test_iteration73_sca03_guide_tooling`: quando `documented_mitigations` é fornecido (como conjunto de CVEs com mitigação verificada pelo laboratório), exigir que `will_not_fix` possua mitigação documentada para não bloquear, e manter `end_of_life` como bloqueante.
2. Remover completamente a lista hardcoded sintética de pacotes Debian 13 em `evaluate_sca03_container_os`, adicionando tentativa direta de `trivy image` remoto (quando não há imagem local no Docker) e coleta de imagens declaradas em `docker-compose*.yml`. Se nenhuma imagem puder ser inspecionada e não houver erro de `FROM` sem digest, retornar `Not_Covered` honesto.
3. Passar `documented_mitigations=set()` (ou CVEs verificados pelo laboratório) na chamada de `parse_trivy_os_report` dentro de `evaluate_sca03_container_os`.
4. Adicionar `test_iteration134_sca03_neon_reeval` em `test_neon_reeval.py`, validar com `test_iteration73_sca03_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-134`.

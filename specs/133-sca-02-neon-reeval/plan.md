# Plano Técnico — SDD 133 (`SCA-02`)

1. Remover heurísticas artificiais de distância de versão major (`Legacy 0.x` / `latest_maj - pinned_maj`) em `evaluate_sca02_dependencies`, mantendo exclusivamente `endoflife.date` (mapa ampliado) + status oficial `deprecated`/`yanked`/`7 - Inactive` do registro e atualizando chave de cache para `v3:`.
2. Adicionar leitura de `package-lock.json` v1 (`dependencies`) e `yarn.lock`, aceitar `https://registry.yarnpkg.com/` como registro canônico e reconhecer mirrors HTTPS PyPI com `--hash=sha256:`/`sha512:` como fixados por digest.
3. Adicionar fallback de cache expirado (`sca02_metadata_cache.json`) e emitir SARIF `level: "note"` para dependências sem resultado no OpenSSF Scorecard.
4. Adicionar `test_iteration133_sca02_neon_reeval` em `test_neon_reeval.py`, validar com `test_iteration72_sca02_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-133`.

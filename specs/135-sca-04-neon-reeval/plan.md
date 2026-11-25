# Plano Técnico — SDD 135 (`SCA-04`)

1. Em `evaluate_sca04_sbom_completeness`, adiar o registro da falha de "SBOM ausente" para *após* tentar localizar o SBOM tanto no repositório quanto no artefato de contêiner (`if pub_sbom_data is None`).
2. Rejeitar valores placeholder NTIA (`""`, `"NOASSERTION"`, `"NONE"`, `"UNKNOWN"`) em `supplier`/`originator`/`author`/`publisher` e `version` (tanto em CycloneDX quanto em SPDX 2.3+, além de verificar `externalRefs` `purl` em SPDX).
3. Normalizar o nome qualificado `group/name` (e matching por `purl` sem qualificadores) tanto nos componentes do avaliador (`syft`) quanto nos componentes publicados ao calcular `Assessor_SBOM − Published_SBOM`.
4. Adicionar `test_iteration135_sca04_neon_reeval` em `test_neon_reeval.py`, validar com `test_iteration74_sca04_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-135`.

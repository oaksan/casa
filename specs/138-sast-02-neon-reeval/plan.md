# Plano Técnico — SDD 138 (`SAST-02`)

1. Adicionar suporte `tarfile` em `evaluate_sast02_trust_material_and_keys` para inspecionar `.tar.gz`, `.tgz` e `.tar` em busca de keystores/certificados e blocos PEM `PRIVATE KEY`.
2. Expandir a varredura de blocos PEM `PRIVATE KEY` para incluir arquivos na raiz e diretórios `app`, `pkg`, `cmd`, `internal`, `services` além dos existentes.
3. Alinhar o rótulo de ferramenta de `SAST-02` em `run_sast_checks` ao `gitleaks` + walker de keystores/artefatos distribuídos (sem `Semgrep`).
4. Adicionar `test_iteration138_sast02_neon_reeval`, validar com `test_iteration77_sast02_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-138`.

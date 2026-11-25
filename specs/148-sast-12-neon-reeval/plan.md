# Plano Técnico — SDD 148 (`SAST-12`)

1. Substituir o bloco hardcoded `if "juice-shop" in img.lower():` em `evaluate_sast12_secrets_management_and_iac` por varredura genérica `trivy image --scanners secret --format json` (ferramenta oficial do Test Guide) sobre qualquer imagem Docker local descoberta via `docker image inspect`.
2. Expandir o inventário de gerenciamento de segredos para detectar também montagens de runtime (`/run/secrets/`, `secretKeyRef`, `secrets-store.csi.k8s.io`) em código/compose/K8s.
3. Ignorar referências `${...}` / `$VAR` em `iac_secret_re` para evitar falsos positivos em templates parametrizados.
4. Adicionar `test_iteration148_sast12_neon_reeval`, validar com `test_iteration87_sast12_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-148`.

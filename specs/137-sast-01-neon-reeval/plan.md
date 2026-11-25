# Plano Técnico — SDD 137 (`SAST-01`)

1. Corrigir a semântica de `verified` em `evaluate_sast01_secrets_and_entropy`: emitir `verified=true` somente quando o detector reportar `Verified=True`, e `verified=false; triaged=error` para achados estáticos de padrão/entropia triados.
2. Adicionar inspeção de segredos dentro de artefatos distribuídos empacotados (`.zip`, `.jar`, `.war`, `.whl`, `.tar.gz`, `.tgz`) e ampliar descoberta genérica de `.env*`/configs/recursos sem depender exclusivamente de caminhos fixos do Juice Shop.
3. Remover o literal específico do Juice Shop de `CASA3-SAST-01-hardcoded-secret` em `casa3_al1_sast.yml` e alinhar o rótulo de ferramenta de `SAST-01` ao ferramental exclusivo do Test Guide (`gitleaks` + detector de padrões/entropia).
4. Adicionar `test_iteration137_sast01_neon_reeval`, validar contra `test_iteration76_sast01_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-137`.

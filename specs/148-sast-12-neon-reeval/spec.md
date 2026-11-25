# SDD 148 — Reavaliação Gemini 4 Neon: Controle 17/61 (`SAST-12`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-12` — *Server-side secrets are held in a managed secrets store, not in config files or environment baked into images*
- **Referências**: ASVS V6.4.1 (L2); CWE-522; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `semgrep`, `trivy`, `docker`
- **Critério de Verificação**:
  - `PASS`: Todo literal correspondente a padrões de segredo confirmado como ativo resolve por meio de chamada a SDK de gerenciador de segredos ou montagem injetada em runtime; nenhum está em arquivos de config, IaC ou camadas de ambiente da imagem.
  - `FAIL`: ≥ 1 segredo fora de SDK de gerenciador de segredos ou montagem em runtime.

## Lacunas Identificadas na Reavaliação
1. **Acoplamento específico ao Juice Shop na inspeção de camadas de imagem (`scanner.py` L3609)**: `if "juice-shop" in img.lower():` verificava 5 caminhos hardcoded (`/juice-shop/ctf.key`, etc.) via `docker run` em vez de inspecionar genericamente camadas de qualquer imagem usando `trivy image --scanners secret`.
2. **Inventário incompleto de montagens em runtime (`Test Guide` L398)**: `evaluate_sast12_secrets_management_and_iac` inventariava apenas SDKs de Secrets Manager, ignorando montagens de segredos em runtime (`/run/secrets/`, `secretKeyRef`, `secrets-store.csi.k8s.io`).
3. **Referências parametrizadas `${VAR}` em IaC**: `iac_secret_re` podia disparar sobre referências de substituição de variável (`${JWT_SECRET}`) em compose/config.

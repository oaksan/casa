# SDD 138 — Reavaliação Gemini 4 Neon: Controle 07/61 (`SAST-02`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-02` — *No private keys, certificates or trust material committed to the repository or shipped in artifacts*
- **Referências**: CWE-321, CWE-798; *ADA-defined*; Profile: `All`
- **Ferramentas de Referência no Test Guide**: `gitleaks`
- **Critério de Verificação**:
  - `PASS`: Zero arquivos de chave privada ou keystore e zero blocos PEM `PRIVATE KEY` no histórico do repositório ou em qualquer artefato distribuído.
  - `FAIL`: ≥ 1 arquivo ou bloco desse tipo.

## Lacunas Identificadas na Reavaliação
1. **Artefatos empacotados em tarball (`.tar.gz`, `.tgz`, `.tar`) não eram inspecionados**: `evaluate_sast02_trust_material_and_keys` abria apenas arquivos baseados em ZIP (`.zip`/`.jar`/`.war`/`.apk`/`.ipa`/`.whl`).
2. **Varredura de blocos PEM `PRIVATE KEY` restrita a 7 subdiretórios fixos**: diretórios comuns (`app`, `pkg`, `cmd`, `internal`, `services`) e arquivos na raiz ficavam fora da inspeção direta de blocos PEM.
3. **Pureza de ferramental (`Test Guide` L183)**: o rótulo de `SAST-02` anunciava `Semgrep AST`, que não é ferramenta de referência para `SAST-02` (o guia lista exclusivamente `gitleaks`).

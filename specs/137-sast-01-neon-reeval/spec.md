# SDD 137 — Reavaliação Gemini 4 Neon: Controle 06/61 (`SAST-01`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-01` — *No hardcoded passwords, API keys, tokens or credentials in source, resources or build config*
- **Referências**: CWE-798; ASVS V2.10.4 (L2); Profile: `All`
- **Ferramentas de Referência no Test Guide**: `gitleaks`, `trufflehog`
- **Critério de Verificação**:
  - `PASS`: Zero achados de segredos em nível `error`, após triagem, em código-fonte, recursos, configuração de build e artefatos distribuídos; qualquer achado verificado como ativo (`verified: true`) é sempre `error`.
  - `FAIL`: ≥ 1 achado de segredo em nível `error` após triagem.

## Lacunas Identificadas na Reavaliação
1. **Marcação artificial de `verified=true` (`scanner.py` L2811/2895/2923/2959)**: o scanner imprimia `verified=true` em todos os achados estáticos do Gitleaks e de regex/entropia mesmo sem verificação ativa contra o serviço emissor.
2. **Ausência de varredura de artefatos distribuídos empacotados (`.zip`, `.jar`, `.whl`, `.tar.gz`)**: o guia exige cobertura sobre *"every shipped artifact"* (L161/L166), mas `SAST-01` inspecionava apenas uma lista fixa de caminhos de código-fonte.
3. **Pureza de ferramental e remoção de literal específico do Juice Shop**: `casa3_al1_sast.yml` continha uma string hardcoded do Juice Shop (`6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie`) e o rótulo de `SAST-01` incluía `Semgrep` (não listado para `SAST-01`, cujo guia especifica `gitleaks` / `trufflehog`).

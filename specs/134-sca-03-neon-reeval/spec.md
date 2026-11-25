# SDD 134 — Reavaliação Gemini 4 Neon: Controle 03/61 (`SCA-03`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SCA-03` — *Container base images and OS packages contain no unmitigated Critical/High CVEs*
- **Referências**: CIS Docker Benchmark §4; *ADA-defined*; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `trivy`, `grype`
- **Critério de Verificação**:
  - `PASS`: Zero achados de pacotes OS ou camada base em severidade `HIGH` ou `CRITICAL` que a distribuição não tenha marcado como `will_not_fix` **com mitigação documentada**.
  - `FAIL`: ≥ 1 achado `HIGH` ou `CRITICAL` na imagem base ou conjunto de pacotes OS que a distribuição não tenha marcado como `will_not_fix` com mitigação documentada.

## Lacunas Identificadas na Reavaliação
1. **Fallback sintético hardcoded para Debian 13 (`scanner.py` L741–753)**: quando Docker/Trivy não encontrava imagem local, o scanner inventava 10 pacotes Debian fixos em código e os consultava na API OSV.dev, violando a autenticidade de evidência do Test Guide e desviando do ferramental normativo (`trivy`/`grype`).
2. **Critério `will_not_fix` com mitigação documentada e status `end_of_life` (`Test Guide` L29, L99–100)**: `parse_trivy_os_report` excluía automaticamente `will_not_fix` mesmo sem mitigação documentada/verificada pelo laboratório, além de excluir `end_of_life`.
3. **Varredura Trivy direta sem Docker daemon & cobertura de `docker-compose*.yml`**: quando o daemon Docker não possuía a imagem em cache local, o scanner não tentava `trivy image` diretamente contra o registro remoto nem coletava imagens declaradas em `docker-compose*.yml`.

# SDD 133 — Reavaliação Gemini 4 Neon: Controle 02/61 (`SCA-02`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SCA-02` — *No component is end-of-life, unmaintained, or sourced from an untrusted repository*
- **Referências**: ASVS V14.2.4 (L2); OpenSSF Scorecard `Maintained`; Profile: `All`
- **Ferramentas de Referência no Test Guide**: `OpenSSF Scorecard`, `endoflife.date`
- **Critério de Verificação**:
  - `PASS`: Toda dependência direta não está além da data publicada de EOL, resolve para o registro público canônico ou mirror controlado pelo desenvolvedor fixado por digest, e — quando existir resultado Scorecard — possui `Maintained >= 5`.
  - `FAIL`: Qualquer dependência direta além da data de EOL, resolvida de outra fonte, ou com Scorecard `Maintained < 5`.

## Lacunas Identificadas na Reavaliação
1. **Heurística artificial de EOL não publicada (`scanner.py` L323–331)**: o código marcava `Legacy 0.x branch` e `latest_maj - pinned_maj >= 2` para `sanitize-html`/`express-jwt`/`jsonwebtoken`, extrapolando o critério normativo ("published EOL date" via `endoflife.date` ou status `deprecated`/`yanked` no registro).
2. **Suporte incompleto a lockfiles e mirrors fixados por digest**: apenas `package-lock.json` v2/v3 (`packages`) era lido (faltando `package-lock.json` v1 e `yarn.lock`) e em PyPI um `--index-url` HTTPS com `--hash=sha256:` não era reconhecido como mirror fixado por digest.
3. **Resiliência de cache e cobertura `endoflife.date`**: falta fallback para cache expirado em falha de rede e ampliação do mapa de produtos oficiais do `endoflife.date`.
4. **Evidência SARIF `note` (`Test Guide` L23)**: dependências sem resultado no OpenSSF Scorecard não geravam nota informativa no SARIF.

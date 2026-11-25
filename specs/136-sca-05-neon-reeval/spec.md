# SDD 136 — Reavaliação Gemini 4 Neon: Controle 05/61 (`SCA-05`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SCA-05` — *No dependency matches a known-malicious package advisory (typosquat, protestware, compromised maintainer)*
- **Referências**: OpenSSF Malicious Packages; CWE-1357; Profile: `All`
- **Ferramentas de Referência no Test Guide**: `osv-scanner`, `OpenSSF malicious-packages feed`
- **Critério de Verificação**:
  - `PASS`: Zero componentes correspondem a um aviso `MAL-`, e zero componentes estão a distância de Levenshtein 1 de um pacote top-10k sob mantenedor diferente.
  - `FAIL`: ≥ 1 componente corresponde a um aviso `MAL-` ou ao predicado de typosquatting.

## Lacunas Identificadas na Reavaliação
1. **Typos em `TOP_CANONICAL_NPM_PACKAGES` e ausência de cobertura PyPI (`scanner.py` L1207/1221/1460)**: entradas com espaços à esquerda (`" eslint-scope"`, `" ngx-cookie"`) e salto explícito (`if eco != "npm": continue`) deixavam pacotes PyPI sem verificação de Levenshtein = 1.
2. **Dependências transitivas de `package-lock.json` / `osv_data` fora da checagem de typosquatting**: o laço de typosquatting iterava apenas manifestos diretos (`pkg_entries`), ignorando dependências transitivas em lockfiles.
3. **Bug de `break` prematuro (`scanner.py` L1494)**: ao encontrar o primeiro candidato canônico a distância 1 com o mesmo mantenedor, o `break` encerrava a busca sem testar outros pacotes canônicos a distância 1.

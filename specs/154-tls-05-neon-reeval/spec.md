# SDD 154 — Reavaliação Gemini 4 Neon: Controle 23/61 (`TLS-05`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `TLS-05` — *`Strict-Transport-Security` present with `max-age` ≥ 31536000*
- **Referências**: ASVS V14.4.5 (L1); Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `testssl.sh`
- **Critério de Verificação**:
  - `PASS`: `HSTS_time` ≥ 31536000 em todo host.
  - `FAIL`: Cabeçalho ausente em qualquer host, ou `max-age` abaixo de 31536000.

## Lacunas Identificadas na Reavaliação
1. **Sintaxe RFC 6797 §6.1 para `max-age` entre aspas (`max-age="31536000"`)**: a regex `max-age\s*=\s*(\d+)` rejeitava `max-age="31536000"` válido pela RFC 6797.
2. **Parsing alternativo de `HSTS_time` no `testssl.sh` e diagnóstico de erro de conexão (`st == 0`)**: `parse_testssl_hsts` aceitava apenas `= <N> seconds` (sem variante entre parênteses `(<N> seconds)`), e falhas de rede `st == 0` eram reportadas como "header ausente".

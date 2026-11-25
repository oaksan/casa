# SDD 145 — Reavaliação Gemini 4 Neon: Controle 14/61 (`SAST-09`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-09` — *Deserialization of untrusted data is avoided or integrity-protected*
- **Referências**: ASVS V5.5.3 (L1); CWE-502; Profile: `All`
- **Ferramentas de Referência no Test Guide**: `semgrep`, `CodeQL`
- **Critério de Verificação**:
  - `PASS`: Zero achados `error` de sink de desserialização de entrada não confiável sem allowlist de tipos, `ObjectInputFilter`, ou verificação de integridade sobre o blob serializado.
  - `FAIL`: ≥ 1 achado `error` sem essas proteções.

## Lacunas Identificadas na Reavaliação
1. **Escopo excessivo de `pattern-not-inside` em Python (`casa3_al1_sast.yml` L617–620)**: um `hmac.compare_digest(...)` em qualquer outra função do mesmo arquivo suprimia um `pickle.loads()` desprotegido em função distinta.
2. **Cobertura multilíngue**: faltavam regras de desserialização insegura para Ruby (`Marshal.load`/`Marshal.restore`/`YAML.load`) e `js-yaml` / Node (`node-serialize` `unserialize`).

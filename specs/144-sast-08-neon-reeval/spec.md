# SDD 144 — Reavaliação Gemini 4 Neon: Controle 13/61 (`SAST-08`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-08` — *Database access exclusively uses parameterized queries, ORMs or escaped input*
- **Referências**: ASVS V5.3.4 (L1); CWE-89; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `CodeQL`, `semgrep`
- **Critério de Verificação**:
  - `PASS`: Zero achados em nível `error` de construção de consulta por concatenação ou interpolação com valor contaminado.
  - `FAIL`: ≥ 1 achado `error` de construção de consulta SQL/NoSQL com entrada contaminada.

## Lacunas Identificadas na Reavaliação
1. **Exclusão excessivamente permissiva em `CASA3-SAST-08-sql-injection` (`casa3_al1_sast.yml` L524–526)**: `pattern-not: "$M.query($X, [ ... ])"` isentava inclusive uma query concatenada caso um segundo argumento array/options fosse passado.
2. **Cobertura multilíngue**: faltavam regras `mode: taint` de SQLi para PHP (`mysqli_query`, `$pdo->query`) e C# (`SqlCommand`, `ExecuteSqlRaw`).

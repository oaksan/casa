# SDD 147 — Reavaliação Gemini 4 Neon: Controle 16/61 (`SAST-11`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-11` — *File paths are not constructed from unvalidated user-supplied metadata*
- **Referências**: ASVS V12.3.1 (L1); CWE-22; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `semgrep`, `CodeQL`
- **Critério de Verificação**:
  - `PASS`: Zero achados `error` de caminho de arquivo construído a partir de metadados do usuário sem validação prévia.
  - `FAIL`: ≥ 1 achado `error` de path traversal sobre metadados fornecidos pelo usuário.

## Lacunas Identificadas na Reavaliação
1. **Sinks de filesystem adicionais em JS/TS**: faltavam `fs.createReadStream`, `fs.unlink`, `fs.unlinkSync` e `fs.promises.unlink`.
2. **Cobertura multilíngue**: faltavam regras `mode: taint` de path traversal (com sanitizadores `basename`/`Path.GetFileName`) para PHP e C#.

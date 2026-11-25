# SDD 140 — Reavaliação Gemini 4 Neon: Controle 09/61 (`SAST-04`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-04` — *No weak hash functions (MD5, SHA-1) used in any security-relevant context*
- **Referências**: CWE-328; NIST SP 800-131A Rev.2; Profile: `All`
- **Ferramentas de Referência no Test Guide**: `semgrep`, `CodeQL`
- **Critério de Verificação**:
  - `PASS`: Zero caminhos de taint em nível `error` de MD5/SHA-1 para um sink relevante de segurança; usos não-seguros (cache key, ETag) são reportados como informativos (`note`/`INFO`).
  - `FAIL`: ≥ 1 caminho de taint em nível `error` de hash fraco para sink de segurança.

## Lacunas Identificadas na Reavaliação
1. **Padrão específico do Juice Shop com risco de falso positivo (`casa3_al1_sast.yml` L155)**: `- pattern: security.hash(...)` disparava independentemente do algoritmo usado por `security.hash` em outras aplicações.
2. **Cobertura multilíngue de taint**: faltavam regras `mode: taint` para PHP (`md5()`/`sha1()`) e C# (`MD5.Create()`/`SHA1.Create()`).
3. **Invariante de log (`scanner.py` L4129)**: o texto de log em `PASS` com avisos ETag usava a palavra `"informational"` em vez de `"note-level"`.

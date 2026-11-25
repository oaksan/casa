# SDD 146 — Reavaliação Gemini 4 Neon: Controle 15/61 (`SAST-10`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-10` — *No dynamic code execution on untrusted input (`eval`, `Function`, `exec`, reflection)*
- **Referências**: ASVS V5.2.4 (L1); CWE-95; Profile: `All`
- **Ferramentas de Referência no Test Guide**: `semgrep`
- **Critério de Verificação**:
  - `PASS`: Zero caminhos de taint em nível `error` de fonte não confiável para sink de execução dinâmica / comando / reflexão.
  - `FAIL`: ≥ 1 caminho de taint `error`.

## Lacunas Identificadas na Reavaliação
1. **Sinks dinâmicos adicionais em JS/TS**: faltavam `spawn(..., { shell: true })`, `child_process.spawn(..., { shell: true })` e `import($MOD)` (carregamento reflexivo dinâmico ESM).
2. **Cobertura multilíngue**: faltavam regras `mode: taint` para PHP (`eval`, `system`, `shell_exec`, `exec`, `passthru`) e C# (`Assembly.Load`, `Process.Start`).

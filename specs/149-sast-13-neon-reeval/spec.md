# SDD 149 — Reavaliação Gemini 4 Neon: Controle 18/61 (`SAST-13`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-13` — *Credentials, payment details and tokens are never written to logs; session tokens appear only in irreversible hashed form*
- **Referências**: ASVS V7.1.1 (L1); CWE-532; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `semgrep`, `scripted replay harness`
- **Critério de Verificação**:
  - `PASS`: Nenhum valor canário aparece literalmente em qualquer registro de log, **e** zero caminhos de taint `error` de credencial, token ou dado de pagamento para sink de log sem mascaramento ou hash irreversível intermediário.
  - `FAIL`: ≥ 1 valor canário literal no log sink, ou ≥ 1 caminho de taint `error` sem mascaramento/hash.

## Lacunas Identificadas na Reavaliação
1. **Fontes sensíveis adicionais em `casa3_al1_sast.yml`**: faltavam `cvv`, `creditCard`, `pan`, `apiKey`, `secret`, `sessionId` em JS/TS e cobertura de taint para PHP (`error_log`, `syslog`).
2. **Harness de replay canário (`evaluate_sast13_canary_log_replay`)**: precisava aceitar caminhos de log extras (`extra_log_paths`), inspecionar arquivos `*.log*` também na raiz do repositório, enviar canário de `cvv` no fluxo de pagamento e confirmar que tokens apenas em forma hash SHA-256 irreversível não geram falso positivo.

# SDD 155 — Reavaliação Gemini 4 Neon: Controle 24/61 (`TLS-06`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `TLS-06` — *No known TLS implementation vulnerabilities (Heartbleed, ROBOT, insecure renegotiation, CRIME)*
- **Referências**: *ADA-defined*; OWASP WSTG-CRYP-01; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `testssl.sh`
- **Critério de Verificação**:
  - `PASS`: Nenhuma entrada na seção de vulnerabilidades reportada em severidade `HIGH` ou `CRITICAL` (incluindo `heartbleed`, `ROBOT`, `secure_renego`, `secure_client_renego`, `CRIME_TLS`, `ticketbleed`); entradas em severidade inferior são reportadas como informativas.
  - `FAIL`: ≥ 1 entrada de vulnerabilidade em severidade `HIGH` ou `CRITICAL`.

## Lacunas Identificadas na Reavaliação
1. **Ausência da entrada explícita `secure_client_renego` (`Test Guide` L549)**: quando `evaluate_tls06_vulnerabilities` complementava `testssl.sh -H -I -T -C` com `secure_renego` e `ROBOT`, faltava registrar explicitamente `secure_client_renego` na saída JSON de vulnerabilidades TLS.

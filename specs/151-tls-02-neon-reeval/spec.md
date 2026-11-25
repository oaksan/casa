# SDD 151 — Reavaliação Gemini 4 Neon: Controle 20/61 (`TLS-02`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `TLS-02` — *Only TLS 1.2 and TLS 1.3 enabled; SSLv3, TLS 1.0 and TLS 1.1 rejected*
- **Referências**: ASVS V9.1.3 (L1); NIST SP 800-52 Rev.2; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `testssl.sh`, `Qualys SSL Labs`
- **Critério de Verificação**:
  - `PASS`: `.protocols` reporta TLS 1.2 ou TLS 1.3 `offered` em todo host declarado, e SSLv2, SSLv3, TLS 1.0 e TLS 1.1 todos `not offered`.
  - `FAIL`: Qualquer um de SSLv2, SSLv3, TLS 1.0 ou TLS 1.1 reportado como `offered`, ou host não completa handshake TLS 1.2/1.3.

## Lacunas Identificadas na Reavaliação
1. **Silenciamento de erros locais do `testssl.sh` (`parse_testssl_protocols`)**: se o `testssl.sh` retornasse `"Local problem"` ou `"not tested"` para SSLv2/SSLv3/TLS 1.0/TLS 1.1, a matriz pré-inicializada com `"not offered"` tratava silenciosamente o protocolo não testado como `"not offered"`.
2. **Sinalização por severidade do `testssl.sh`**: entradas de protocolos obsoletos com `severity` `HIGH`/`CRITICAL` (mesmo com texto alternativo como `"offered (deprecated)"`) devem ser classificadas de forma determinística como `"offered"`.

# SDD 153 — Reavaliação Gemini 4 Neon: Controle 22/61 (`TLS-04`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `TLS-04` — *Certificate chain is valid, trusted, unexpired and matches the hostname*
- **Referências**: ASVS V9.2.1 (L2); CA/Browser Forum Baseline Requirements; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `testssl.sh`, `Qualys SSL Labs`
- **Critério de Verificação**:
  - `PASS`: Cadeia valida até raiz pública, certificado não expirado no momento da varredura, e CN/SAN corresponde a todo host testado; tempo restante < 30 dias reportado como aviso.
  - `FAIL`: Qualquer erro de cadeia, certificado expirado/ainda não válido, ou incompatibilidade de hostname.

## Lacunas Identificadas na Reavaliação
1. **Validação de `notBefore` (certificado futuro) e negações explícitas de confiança/hostname (`parse_testssl_certificate`)**: não checava certificados ainda não válidos (`notBefore > now`) nem guardava contra achados contendo `"mismatch"`/`"does not match"`/`"self-signed"`/`"not trusted"`.
2. **Higiene textual SDD 070 em avisos `< 30 days`**: o aviso usava o prefixo `"Informational:"`, podendo violar a invariante de log do SDD 070 caso emitido em `PASS`.

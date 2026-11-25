# SDD 152 — Reavaliação Gemini 4 Neon: Controle 21/61 (`TLS-03`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `TLS-03` — *Only strong cipher suites; NULL, EXPORT, anonymous, RC4 and legacy CBC suites rejected; forward secrecy preferred*
- **Referências**: ASVS V9.1.2 (L1); NIST SP 800-52 Rev.2; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `testssl.sh`, `Qualys SSL Labs`
- **Critério de Verificação**:
  - `PASS`: Nenhuma suíte NULL, EXPORT, anônima, RC4, 3DES ou CBC-SHA1 é oferecida, e toda suíte TLS 1.2 oferecida provê forward secrecy.
  - `FAIL`: ≥ 1 suíte da lista banida (NULL, EXPORT, anônima, RC4, 3DES, CBC-SHA1) é oferecida, ou ≥ 1 suíte TLS 1.2 sem forward secrecy é oferecida.

## Lacunas Identificadas na Reavaliação
1. **Inspeção incompleta de `cipherlist_AVERAGE` e nomes individuais de suítes CBC-SHA1 (`parse_testssl_ciphers`)**: `parse_testssl_ciphers` ignorava `cipherlist_AVERAGE` e não inspecionava os nomes individuais retornados em `FS_ciphers` (onde suítes ECDHE CBC-SHA1 como `ECDHE-RSA-AES128-SHA` / `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` podem aparecer como FS mesmo sendo banidas pela regra CBC-SHA1).

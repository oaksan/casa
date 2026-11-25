# Plano Técnico — SDD 152 (`TLS-03`)

1. Expandir `parse_testssl_ciphers` em `scanner.py` para detectar `cipherlist_AVERAGE` quando oferecido e inspecionar nomes individuais em `FS_ciphers` / entradas `cipher-*` contra a lista normativa banida (`NULL`, `EXPORT`, `aNULL`/`ADH`/`AECDH`, `RC4`, `3DES`/`DES-CBC3`, e `CBC-SHA1`).
2. Adicionar `test_iteration152_tls03_neon_reeval` cobrindo `ECDHE-RSA-AES128-SHA` / `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` e `cipherlist_AVERAGE` oferecidos, validar contra `test_iteration91_tls03_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-152`.

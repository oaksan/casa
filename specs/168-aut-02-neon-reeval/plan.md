# Plano Técnico — SDD 168 (AUT-02)

1. Aprimorar `estimate_sp800_90b_token_min_entropy` em `casa-assessment/casa_audit/scanner.py`:
   - Deduplicar colunas bijetivamente correlacionadas entre as amostras (assinatura de partição por ordem de primeira aparição).
   - Calcular limite superior de compressão (`zlib` nível 9 em bits por token) e tomar `min(pos_ucb_bits, compression_bits_per_token)` como `effectiveMinEntropyBits`.
2. Adicionar teste unitário `test_iteration168_aut02_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-168` e fazer push.

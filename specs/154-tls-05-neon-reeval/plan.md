# Plano Técnico — SDD 154 (`TLS-05`)

1. Atualizar `parse_testssl_hsts` para aceitar tanto `= <N> seconds` quanto `(<N> seconds)`.
2. Atualizar `evaluate_tls05_hsts_enforcement` para aceitar `max-age="31536000"` (RFC 6797 §6.1) e distinguir falhas de conexão (`st == 0`) de ausência de cabeçalho HSTS.
3. Adicionar `test_iteration154_tls05_neon_reeval`, validar contra `test_iteration93_tls05_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-154`.

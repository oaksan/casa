# Plano Técnico — SDD 153 (`TLS-04`)

1. Reforçar `parse_testssl_certificate` em `scanner.py` para verificar `notBefore <= now` (rejeitando certificados futuros), rejeitar explicitamente `"self-signed"`/`"not trusted"`/`"mismatch"`/`"does not match"` em `cert_chain_of_trust`/`cert_trust`, e usar o prefixo `"Advisory (< 30 days):"` no aviso de expiração próxima.
2. Adicionar `test_iteration153_tls04_neon_reeval`, validar contra `test_iteration92_tls04_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-153`.

# Plano Técnico — SDD 150 (`TLS-01`)

1. Restringir `valid_https_redirect` em `evaluate_tls01_transport_enforcement` aos códigos de redirecionamento HTTP válidos `{301, 302, 303, 307, 308}` com `Location` de esquema `https` apontando ao mesmo host.
2. Adicionar parâmetro opcional `endpoints: list[str] | None = None` mantendo compatibilidade retroativa com chamadas existentes.
3. Adicionar `test_iteration150_tls01_neon_reeval`, validar contra `test_iteration89_tls01_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-150`.

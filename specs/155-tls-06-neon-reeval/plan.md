# Plano Técnico — SDD 155 (`TLS-06`)

1. Adicionar verificação explícita de `secure_client_renego` em `evaluate_tls06_vulnerabilities` quando não presente em `seen_ids` (usando `openssl s_client` não-bloqueante para validar se renegociação iniciada pelo cliente é rejeitada ou aceita).
2. Adicionar `test_iteration155_tls06_neon_reeval` validando que `LOW`/`MEDIUM` não bloqueia `PASS`, que `HIGH`/`CRITICAL` em `secure_client_renego`/`ROBOT`/`heartbleed` causa `FAIL`, e que `secure_client_renego` é incluído na auditoria.
3. Validar contra `test_iteration94_tls06_guide_tooling`, executar fechamento do Domínio 3 (`unittest discover` integral + varredura ao vivo contra OWASP Juice Shop verificando `TLS-01..TLS-06`), documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-155`.

# Plano — SDD 192 (WHK-03 + Fechamento Final da Série 61/61)

1. Atualizar `evaluate_whk03_ssrf_and_signing_secrets` em `casa-assessment/casa_audit/scanner.py`:
   - Adicionar vetores `ula_ipv6_fc00` (`fc00::/7`) e `ipv4_mapped_ipv6_loopback` (`::ffff:127.0.0.1`) a `ssrf_vectors` (total de 13 vetores).
   - Expandir `assign_sec_re` com `webhook_signing_key`, `webhookSigningKey` e `x-webhook-secret`.
   - Aplicar guarda `not _is_json_denial(r_body)` (Guia L25) em respostas HTTP 2xx de registro sem fetch OOB.
2. Atualizar `test_iteration131_whk03_guide_tooling` (`probesRun >= 11`) e criar `test_iteration192_whk03_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Executar suíte completa `unittest discover` (125 testes `OK`) + reiniciar daemon `casa_audit` e executar scan ao vivo completo contra OWASP Juice Shop cobrindo todos os 61/61 controles.
4. Registrar fechamento do Domínio 8 e consolidação final da série (`SDD 132`–`SDD 192`, 61/61 controles, zero Burp Suite pago) em `docs/justificativaNeon.txt`, commitar, criar tag `sdd-192` e fazer push.

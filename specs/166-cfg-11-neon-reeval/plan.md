# Plano Técnico — SDD 166 (CFG-11, Encerramento do Domínio 4)

1. Expandir `takeover_fingerprints` em `evaluate_cfg11_dns_takeover` (`casa-assessment/casa_audit/scanner.py`) para 24 provedores `can-i-take-over-xyz`.
2. Adicionar parâmetro opcional `extra_hosts: list[str] | None = None` para resolver e auditar múltiplos subdomínios em escopo.
3. Adicionar teste unitário `test_iteration166_cfg11_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
4. Rodar suíte completa `unittest discover` (99 testes), reiniciar daemon `casa_audit` e executar scan live completo no OWASP Juice Shop.
5. Registrar resumo empírico do Domínio 4 em `docs/justificativaNeon.txt`, commitar, taggear `sdd-166` e enviar ao remoto.

# Plano Técnico — SDD 167 (AUT-01)

1. Atualizar `evaluate_aut01_default_credentials` em `casa-assessment/casa_audit/scanner.py` para:
   - Aceitar `login_endpoints: list[str] | None = None`.
   - Expandir mapeamento dinâmico de credenciais padrão derivadas de `cfg03_findings` (Tomcat, Jenkins, Grafana, Kibana/Elasticsearch, RabbitMQ, phpMyAdmin, Spring).
   - Detectar autenticação bem-sucedida também em respostas `302`/`303` acompanhadas de `Set-Cookie` de sessão.
2. Adicionar teste unitário `test_iteration167_aut01_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-167` e fazer push.

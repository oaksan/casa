# Plano Técnico — SDD 158 (CFG-03)

1. Introduzir `non_product_prefixes` em `evaluate_cfg03_version_disclosure` (`casa-assessment/casa_audit/scanner.py`) para filtrar tokens de protocolos/especificações (`HTTP/`, `TLS/`, `SSL/`, `OAUTH/`, `OPENAPI/`, `MIME/`, `SPDX/`, `JSON/`, `XML/`, `UTF/`, `HTML/`, `CSS/`, `SVG/`, `REST/`, `GRAPHQL/`, `GRPC/`) tanto em cabeçalhos quanto em corpos.
2. Adicionar teste unitário `test_iteration158_cfg03_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Registrar justificativa em `docs/justificativaNeon.txt`, rodar testes unitários + regressão, commitar, taggear `sdd-158` e enviar ao remoto.

# Plano Técnico — SDD 177 (AZI-03)

1. Expandir `_count_json_records` em `casa-assessment/casa_audit/scanner.py` para contar coleções em `data`, `items`, `results`, `records`, `rows` e `users`.
2. Expandir a lista de marcadores de erro SQL em `evaluate_azi03_sqli_nosql` (PostgreSQL/MSSQL/MySQL) e suportar `method: "GET"` em `nosql_query_targets`.
3. Adicionar teste unitário `test_iteration177_azi03_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
4. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-177` e enviar ao remoto.

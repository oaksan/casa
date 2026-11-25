# SDD 177 — AZI-03 Reavaliação Neon (SQL & NoSQL Query Safety)

## Controle Alvo
- **ID:** `AZI-03` (Controle `46/61`, Domínio 6 — Authorization & Injection)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 1008–1026)
- **Ferramentas de Referência do Guia:** `sqlmap, ZAP, Burp Suite, Schemathesis`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita — SEM Burp Suite pago):** Utiliza `sqlmap` oficial + OWASP ZAP 2.17.0 (regras `40018`/`40024`) + verificador diferencial de conjunto de resultados com SARIF 2.1.0 e HAR 1.2 redigido.
2. **Lacuna 1 — Cobertura de chaves JSON em `_count_json_records`:** O contador diferencial inspecionava apenas `data` e `items`, ignorando coleções REST comuns como `results`, `records`, `rows` e `users`.
3. **Lacuna 2 — Assinaturas de erro de banco de dados:** Faltavam marcadores padronizados de PostgreSQL (`syntax error at or near`, `pg_query`) e MSSQL (`unclosed quotation mark`, `microsoft ole db`).
4. **Lacuna 3 — Suporte a `method: "GET"` em `nosql_query_targets`:** `nosql_query_targets` só suportava `POST` JSON, não cobrindo endpoints `GET` que parseiam parâmetros de filtro na query string.

## Critérios de Aceitação
- `_count_json_records` reconhece `data`, `items`, `results`, `records`, `rows` e `users`.
- Detecção de erro SQL 5xx cobre PostgreSQL, MSSQL, MySQL, Oracle e SQLite.
- `nosql_query_targets` suporta `method: "GET"` além de `POST`.
- Regressão (`test_iteration116_azi03_guide_tooling`) e novo teste (`test_iteration177_azi03_neon_reeval`) passam 100%.

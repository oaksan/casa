# SDD 164 — CFG-09 Reavaliação Neon (Error Handling Without Information Disclosure)

## Controle Alvo
- **ID:** `CFG-09` (Controle `33/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 723–741)
- **Ferramentas de Referência do Guia:** `OWASP ZAP (rule 90022 Application Error Disclosure)`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza OWASP ZAP 2.17.0 (Regra Passiva `90022`) + sonda 4xx/5xx de vazamento de erros. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Cobertura multi-linguagem de stack traces e erros SQL:** `error_leak_patterns` não cobria frames isolados de Python (`File "*.py", line N`), erros fatais/traces de PHP (`Fatal error: ... on line N`, `Stack trace: #0`), backtraces de Ruby (`.rb:N:in`), panics de Go (`goroutine N [running]:`) e erros SQL de PDO/ODBC/psycopg2/MSSQL (`SQLSTATE[...]`, `System.Data.SqlClient`).
3. **Lacuna 2 — Sonda JSON malformado:** `cfg09_probes` enviava payload oversize e tipo inválido, mas não enviava JSON sintaticamente malformado (`{invalid-json`) para provocar exceções de parser.

## Critérios de Aceitação
- `evaluate_cfg09_error_disclosure` detecta vazamentos 4xx/5xx em Python, PHP, Ruby, Go e SQLSTATE/SqlClient.
- `cfg09_probes` inclui sonda `POST` com JSON sintaticamente malformado.
- Respostas genéricas (`{"error":"Invalid request"}`) continuam `PASS`.
- Regressão (`test_iteration103_cfg09_guide_tooling`) e novo teste (`test_iteration164_cfg09_neon_reeval`) passam 100%.

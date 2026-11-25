# Plano Técnico — SDD 164 (CFG-09)

1. Expandir `error_leak_patterns` em `evaluate_cfg09_error_disclosure` (`casa-assessment/casa_audit/scanner.py`) com assinaturas de stack frames Python/PHP/Ruby/Go e erros SQL (`SQLSTATE[...]`, `System.Data.SqlClient`, `psycopg2.*Error`, `ActiveRecord::StatementInvalid`).
2. Adicionar sonda `POST` com JSON malformado (`b"{invalid-json"`) em `cfg09_probes`.
3. Adicionar teste unitário `test_iteration164_cfg09_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
4. Documentar em `docs/justificativaNeon.txt`, rodar testes unitários + regressão, commitar, taggear `sdd-164` e enviar ao remoto.

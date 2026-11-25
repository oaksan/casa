# Plano Técnico — SDD 174 (AUT-08, Encerramento do Domínio 5)

1. Aprimorar `_scan_storage_snapshot` em `casa-assessment/casa_audit/scanner.py`:
   - Detectar PANs formatados (`\d[ -]?`) com validação Luhn após remoção de separadores.
   - Inspecionar recursivamente objetos JSON serializados em busca de chaves aninhadas de material de autenticação (`access_token`, `refresh_token`, `id_token`, `password`, `session_id`, `client_secret`) com valor não-vazio.
   - Comparar valores de perfil IdP (`len >= 6`) de forma case-insensitive.
2. Adicionar teste unitário `test_iteration174_aut08_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Rodar suíte completa `unittest discover` (107 testes), reiniciar daemon `casa_audit` e executar scan live completo no OWASP Juice Shop.
4. Registrar resumo empírico do Domínio 5 em `docs/justificativaNeon.txt`, commitar, taggear `sdd-174` e fazer push.

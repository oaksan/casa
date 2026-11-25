# Plano Técnico — SDD 156 (CFG-01)

1. Ampliar `parse_directory_index_body` em `casa-assessment/casa_audit/scanner.py` para reconhecer:
   - Azure Blob Storage `<EnumerationResults>` XML (extração de `<Name>`).
   - Autoindex IIS (`[to parent directory]`) e Tomcat (`directory listing for `).
2. Adicionar teste unitário `test_iteration156_cfg01_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar auditoria e validação em `docs/justificativaNeon.txt`.
4. Executar `test_iteration156_cfg01_neon_reeval` e `test_iteration95_cfg01_guide_tooling`, commitar, taggear `sdd-156` e enviar ao remoto.

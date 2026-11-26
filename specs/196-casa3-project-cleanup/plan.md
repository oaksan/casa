# Plano — SDD 196 (Limpeza do Projeto CASA 3.0)

1. Atualizar `.gitignore` para ignorar `casa-assessment/output/*` (preservando `!casa-assessment/output/.gitkeep`) e criar `casa-assessment/output/.gitkeep`.
2. Remover via `git rm -r` os diretórios/arquivos alheios ao CASA 3.0 (perfis AI/Cloud/MASA/DASA/Meta/Mobile/Web, `Submission Forms and Templates`, `assessment`, `cloud-assessment`, `scripts`, `.github`, `ADA_*.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CASA/{ADA Burp*,CASA Specification.md,CASA Test Guide.md}`, `casa-assessment/samples`).
3. Remover do índice Git (`git rm --cached`) os 93 artefatos efêmeros em `casa-assessment/output/` e limpar apenas arquivos efêmeros em disco, preservando `applications.json` e `scan_history.json`.
4. Adicionar `test_iteration196_casa3_project_cleanup` em `casa-assessment/tests/test_neon_reeval.py` validando remoção dos desnecessários e integridade de todas as dependências de runtime, executar testes + iniciar servidor `casa_audit` + verificar saúde HTTP, commitar, criar tag `sdd-196` e fazer push.

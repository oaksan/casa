# SDD 196 — Limpeza do Projeto para Manter Apenas Arquivos Necessários do CASA 3.0

## Objetivo
Reduzir o número de arquivos desnecessários no repositório mantendo **100% dos arquivos, regras, scripts, especificações e dependências necessárias** para execução, geração de dados e testes da aplicação **CASA 3.0**.

## Escopo Aprovado
- **Removidos (alheios ao CASA 3.0):**
  - Perfis/projetos upstream não-CASA-3.0: `AI Profile/`, `Cloud App and Config Profile/`, `DASA/`, `MASA/`, `Meta Profile Extension/`, `Mobile App Profile/`, `Web App Profile/`, `Submission Forms and Templates/`, `assessment/`, `cloud-assessment/`, `scripts/` (linters AI/upstream na raiz), `.github/`.
  - Documentos upstream da raiz: `ADA_Evaluation_Methodology.md`, `ADA_Scheme_Overview.md`, `ADA_Security_Test_Lab_Authorization.md`, `CHANGELOG.md`, `CONTRIBUTING.md`.
  - Arquivos legados CASA v2 e Burp pago em `CASA/`: `CASA/ADA Burp Audit Scan Configuration.json`, `CASA/CASA Specification.md`, `CASA/CASA Test Guide.md`.
  - Exemplos legados não usados em runtime: `casa-assessment/samples/`.
- **Desversionados (artefatos gerados em runtime):**
  - 93 artefatos gerados em `casa-assessment/output/` removidos do controle de versão via `git rm --cached` + regra `casa-assessment/output/*` e `!casa-assessment/output/.gitkeep` no `.gitignore` (preservando dados locais do usuário como `applications.json` e `scan_history.json` em disco).
- **Preservados integralmente:**
  - `casa-assessment/{casa_audit,frontend,data,rules,scripts,tests,README.md}`
  - Os 4 documentos oficiais CASA 3.0 em `CASA/` (`AL1/AL2 Specification.md` e `Test Guide.md`)
  - `specs/`, `docs/`, `.specify/`, `.gemini/`, `LICENSE`, `README.md`.

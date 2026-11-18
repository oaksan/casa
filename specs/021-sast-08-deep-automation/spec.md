# Feature Specification: SDD Iteration 21 — Deep AL1 Automation & Academic Justification for Control SAST-08

**Feature Branch**: `021-sast-08-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 13/61: `SAST-08`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-08 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-08` (*"Database access exclusively uses parameterized queries, ORMs or escaped input"*) detecte via Semgrep AST tanto construções SQL não parametrizadas (`sequelize.query`, `db.query`, Python `cursor.execute`) quanto injeções NoSQL via operador `$where` (`$COLL.find({ $where: ... })`).

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop e verificar que tanto as rotas de SQL Injection (`routes/login.ts:34`, `routes/search.ts:23`) quanto as 3 rotas de NoSQL Injection `$where` (`routes/trackOrder.ts:18`, `routes/showProductReviews.ts:36`, `routes/chat.ts:149`) são detectadas em `output/semgrep-sast.sarif`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE expandir `CASA3-SAST-08-sql-injection` para cobrir SQL e NoSQL (`$where`) por interpolação ou concatenação, e adicionar `CASA3-SAST-08-sql-nosql-python`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 13/61: SAST-08 (Iteração SDD 021)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-021` e sincronizado no GitHub.

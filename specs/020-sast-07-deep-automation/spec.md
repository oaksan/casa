# Feature Specification: SDD Iteration 20 — Deep AL1 Automation & Academic Justification for Control SAST-07

**Feature Branch**: `020-sast-07-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 12/61: `SAST-07`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-07 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-07` (*"Frameworks protect against mass assignment / unsafe auto-binding"*) execute tanto a análise estática de auto-binders irrestritos (`Semgrep AST` sobre `finale.resource(...)`, `.create(req.body)`, `.update(req.body)`, `{ ...req.body }`) quanto a sonda ativa de injeção de campo privilegiado (`"role": "admin"` em `POST /api/Users/`), confirmando se o campo privilegiado é persistido e retornado.

**Independent Test**: Executar `run_sast_checks()` + `evaluate_sast07_mass_assignment_probe("http://localhost:3000")` contra o OWASP Juice Shop (`FAIL` com `server.ts:529` e `HTTP 201 role="admin"`).

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE expandir `CASA3-SAST-07-mass-assignment` e adicionar `CASA3-SAST-07-mass-assignment-python`.
- **FR-002**: `casa-assessment/casa_audit/scanner.py` DEVE implementar `evaluate_sast07_mass_assignment_probe(target_url)` integrada a `run_automated_al1_scan()`.
- **FR-003**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 12/61: SAST-07 (Iteração SDD 020)`.
- **FR-004**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-020` e sincronizado no GitHub.

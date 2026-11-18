# Feature Specification: SDD Iteration 26 — Deep AL1 Automation & Academic Justification for Control SAST-13

**Feature Branch**: `026-sast-13-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 18/61: `SAST-13`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-13 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-13` (*"Credentials, payment details and tokens are never written to logs; session tokens appear only in irreversible hashed form"*) execute tanto regras estáticas `mode: taint` / AST (incluindo senhas passadas por `GET` query parameters para access logs `morgan`) quanto o **Scripted Canary Replay Harness** sobre os fluxos de autenticação/troca de senha com inspeção direta de `logs/access.log.*`.

**Independent Test**: Executar `run_sast_checks()` + `evaluate_sast13_canary_log_replay("http://localhost:3000", repo)` contra o OWASP Juice Shop e verificar a transição do antigo falso `PASS` para `FAIL` (`routes/changePassword.ts:14` + `logs/access.log.*` contendo o valor canário em texto claro).

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE converter `CASA3-SAST-13-sensitive-logging` para `mode: taint`, adicionar `CASA3-SAST-13-get-password-query-logged` e adicionar `CASA3-SAST-13-sensitive-logging-python`.
- **FR-002**: `casa-assessment/casa_audit/scanner.py` DEVE implementar `evaluate_sast13_canary_log_replay(target_url, repo)` integrada em `run_automated_al1_scan()`.
- **FR-003**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 18/61: SAST-13 (Iteração SDD 026)`.
- **FR-004**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-026` e sincronizado no GitHub.

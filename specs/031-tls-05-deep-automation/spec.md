# Feature Specification: SDD Iteration 31 — Deep AL1 Automation & Academic Justification for Control TLS-05

**Feature Branch**: `031-tls-05-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 23/61: `TLS-05`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for TLS-05 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `TLS-05` (*"`Strict-Transport-Security` present with `max-age` ≥ 31536000"*) inspecione múltiplos endpoints HTML/API (`/`, `/api/Products`, `/rest/admin/application-configuration`), extraia `HSTS_time`, `includeSubDomains` e `preload`, valide RFC 6797 §7.2 (sobre HTTPS) e registre `HSTS_time` e `tls05Hsts` em `output/tls-scan.json`.

**Independent Test**: Executar `run_dynamic_and_protocol_checks("http://localhost:3000", repo)` contra o OWASP Juice Shop e verificar `FAIL` com `HSTS_time = 0` e 3 endpoints ausentes registrados em `output/tls-scan.json`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/casa_audit/scanner.py` DEVE auditar múltiplos endpoints HSTS, validar RFC 6797 §7.2 e persistir `HSTS_time` / `tls05Hsts` em `output/tls-scan.json`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 23/61: TLS-05 (Iteração SDD 031)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-031` e sincronizado no GitHub.

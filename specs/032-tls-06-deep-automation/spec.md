# Feature Specification: SDD Iteration 32 — Deep AL1 Automation & Academic Justification for Control TLS-06

**Feature Branch**: `032-tls-06-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 24/61: `TLS-06`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for TLS-06 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `TLS-06` (*"No known TLS implementation vulnerabilities (Heartbleed, ROBOT, insecure renegotiation, CRIME)"*) execute sondas reais de `heartbleed`, `CRIME_TLS`, `secure_renego`, `ROBOT` e `ticketbleed` com classificação por severidade (`HIGH`/`CRITICAL`) e persista `.vulnerabilities` e `tls06ImplementationVulnerabilities` em `output/tls-scan.json`.

**Independent Test**: Executar `run_dynamic_and_protocol_checks("http://localhost:3000", repo)` contra o OWASP Juice Shop e verificar `FAIL` com `.vulnerabilities` gravado em `output/tls-scan.json`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/casa_audit/scanner.py` DEVE implementar `probe_tls_vulnerabilities()` e persistir `.vulnerabilities` / `tls06ImplementationVulnerabilities` em `output/tls-scan.json`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 24/61: TLS-06 (Iteração SDD 032)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-032` e sincronizado no GitHub.

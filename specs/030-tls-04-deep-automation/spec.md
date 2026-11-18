# Feature Specification: SDD Iteration 30 — Deep AL1 Automation & Academic Justification for Control TLS-04

**Feature Branch**: `030-tls-04-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 22/61: `TLS-04`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for TLS-04 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `TLS-04` (*"Certificate chain is valid, trusted, unexpired and matches the hostname"*) valide a cadeia X.509 contra a store raiz pública, extraia `subject`, `issuer`, `SANs`, `notBefore`, `notAfter`, calcule `remainingDays` (reportando alerta informacional se `< 30 dias`), verifique CN/SAN contra o host declarado e grave `.certificate` em `output/tls-scan.json`.

**Independent Test**: Executar `run_dynamic_and_protocol_checks("http://localhost:3000", repo)` contra o OWASP Juice Shop e verificar `FAIL` com `.certificate` e `tls04CertificateValidation` gravados em `output/tls-scan.json`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/casa_audit/scanner.py` DEVE implementar `probe_x509_certificate()` e persistir `.certificate` / `tls04CertificateValidation` em `output/tls-scan.json`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 22/61: TLS-04 (Iteração SDD 030)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-030` e sincronizado no GitHub.

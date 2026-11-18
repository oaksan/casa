# Feature Specification: SDD Iteration 27 — Deep AL1 Automation & Academic Justification for Control TLS-01

**Feature Branch**: `027-tls-01-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 19/61: `TLS-01`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for TLS-01 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `TLS-01` (*"TLS enforced on all endpoints; no cleartext fallback; HTTP redirects to HTTPS"*) execute handshake TLS real no host alvo, sonde endpoints HTTP em texto claro com `follow_redirects=False` para verificar recusa/timeout ou redirecionamento `3xx` para `https://<mesmo-host>/`, e gere o artefato JSON máquina-legível (`output/tls-scan.json`).

**Independent Test**: Executar `run_dynamic_and_protocol_checks("http://localhost:3000", repo)` contra o OWASP Juice Shop e verificar o veredito `FAIL` com as 4 violações de texto claro e a criação de `casa-assessment/output/tls-scan.json`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/casa_audit/scanner.py` DEVE implementar a sonda multi-endpoint `follow_redirects=False`, validação de `Location: https://<host>` e geração de `casa-assessment/output/tls-scan.json`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 19/61: TLS-01 (Iteração SDD 027)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-027` e sincronizado no GitHub.

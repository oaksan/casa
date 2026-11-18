# Feature Specification: SDD Iteration 28 — Deep AL1 Automation & Academic Justification for Control TLS-02

**Feature Branch**: `028-tls-02-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 20/61: `TLS-02`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for TLS-02 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `TLS-02` (*"Only TLS 1.2 and TLS 1.3 enabled; SSLv3, TLS 1.0 and TLS 1.1 rejected"*) teste individualmente todas as 6 versões SSL/TLS (`SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`, `TLS 1.2`, `TLS 1.3`) no endpoint declarado, registre o dicionário `.protocols` em `output/tls-scan.json` e só aprove (`PASS`) quando `TLS 1.2` ou `TLS 1.3` estiverem `offered` **e** todas as versões legadas estiverem `not offered`.

**Independent Test**: Executar `run_dynamic_and_protocol_checks("http://localhost:3000", repo)` e verificar que `.protocols` foi gravado em `output/tls-scan.json` e `TLS-02` retorna `FAIL` porque nem `TLS 1.2` nem `TLS 1.3` estão `offered`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/casa_audit/scanner.py` DEVE implementar `probe_protocol_matrix` (raw ClientHello para `SSLv2`/`SSLv3` + handshake isolado com `ALL:@SECLEVEL=0` para `TLS 1.0..1.3`) e persistir `.protocols` em `output/tls-scan.json`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 20/61: TLS-02 (Iteração SDD 028)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-028` e sincronizado no GitHub.

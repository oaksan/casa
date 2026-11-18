# Feature Specification: SDD Iteration 29 — Deep AL1 Automation & Academic Justification for Control TLS-03

**Feature Branch**: `029-tls-03-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 21/61: `TLS-03`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for TLS-03 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `TLS-03` (*"Only strong cipher suites; NULL, EXPORT, anonymous, RC4 and legacy CBC suites rejected; forward secrecy preferred"*) sonde ativamente cada categoria banida (`NULL`, `EXPORT`, `aNULL`, `RC4`, `3DES`, `CBC-SHA1`), verifique ausência de troca `RSA` estática sem Forward Secrecy no TLS 1.2, confirme oferta de suítes fortes AEAD + FS e registre `.cipherSuites` e `tls03CipherEnforcement` em `output/tls-scan.json`.

**Independent Test**: Executar `run_dynamic_and_protocol_checks("http://localhost:3000", repo)` contra o OWASP Juice Shop e verificar `FAIL` com `.cipherSuites` persistido em `output/tls-scan.json`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/casa_audit/scanner.py` DEVE implementar `probe_cipher_suites()` e registrar `.cipherSuites` / `tls03CipherEnforcement` em `output/tls-scan.json`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 21/61: TLS-03 (Iteração SDD 029)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-029` e sincronizado no GitHub.

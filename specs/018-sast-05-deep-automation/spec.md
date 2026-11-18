# Feature Specification: SDD Iteration 18 — Deep AL1 Automation & Academic Justification for Control SAST-05

**Feature Branch**: `018-sast-05-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 10/61: `SAST-05`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-05 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-05` (*"Passwords stored using an approved memory-hard KDF with per-user salt"*) localize os sinks de persistência de senha (`models/user.ts:73`) e valide os parâmetros de custo do NIST SP 800-63B §5.1.1.2 (`Argon2id m >= 19456 KiB & t >= 2`, `scrypt N >= 32768`, `bcrypt cost >= 10`, `PBKDF2 >= 600000` com salt CSPRNG por registro).

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop (`FAIL` detectando `lib/insecurity.ts:41` e `models/user.ts:73`) e validar que `evaluate_sast05_password_kdf()` rejeita custos abaixo do piso NIST SP 800-63B.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE expandir `CASA3-SAST-05-weak-password-kdf` para sinks de persistência de senha e salts estáticos em PBKDF2.
- **FR-002**: `casa-assessment/casa_audit/scanner.py` DEVE implementar `evaluate_sast05_password_kdf(repo)`.
- **FR-003**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 10/61: SAST-05 (Iteração SDD 018)`.
- **FR-004**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-018` e sincronizado no GitHub.

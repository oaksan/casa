# Feature Specification: SDD Iteration 16 — Deep AL1 Automation & Academic Justification for Control SAST-03

**Feature Branch**: `016-sast-03-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 08/61: `SAST-03`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-03 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-03` (*"No deprecated or broken cipher algorithms (DES, 3DES, RC4, Blowfish, ECB mode)"*) detecte via Semgrep AST todas as variantes de algoritmos banidos (`DES`, `3DES`, `RC4`, `Blowfish`, modo `ECB`) tanto em Node.js/TypeScript (`crypto`, `CryptoJS`) quanto em Python (`PyCryptodome`, `cryptography`).

**Independent Test**: Executar `run_sast_checks()` contra um fixture vulnerável com `des-ede3-cbc`, `aes-256-ecb`, `CryptoJS.RC4`, `DES.new` e `AES.MODE_ECB` (`FAIL` com 5 achados) e contra o OWASP Juice Shop (`PASS` sem falsos positivos).

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE cobrir `CASA3-SAST-03-weak-cipher` (JS/TS) e `CASA3-SAST-03-weak-cipher-python` (Python).
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 08/61: SAST-03 (Iteração SDD 016)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-016` e sincronizado no GitHub.

# Feature Specification: SDD Iteration 17 — Deep AL1 Automation & Academic Justification for Control SAST-04

**Feature Branch**: `017-sast-04-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 09/61: `SAST-04`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-04 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-04` (*"No weak hash functions (MD5, SHA-1) used in any security-relevant context"*) detecte via Semgrep AST tanto as fontes (`createHash('md5'|'sha1')`, `createHmac('md5'|'sha1')`, `CryptoJS.MD5/SHA1`, `hashlib.md5/sha1`) quanto os sorvedouros críticos de segurança (`$SEC.hash(...)` em persistência de senhas, login, 2FA e assinaturas).

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop e verificar que os 15 achados (incluindo `lib/utils.ts:82` HMAC-SHA1, `lib/insecurity.ts:41` MD5 e os sinks em `models/user.ts`, `routes/login.ts`, `routes/changePassword.ts`, `routes/2fa.ts`) são detectados e gravados em `output/semgrep-sast.sarif`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE expandir `CASA3-SAST-04-weak-hash` e adicionar `CASA3-SAST-04-weak-hash-python`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 09/61: SAST-04 (Iteração SDD 017)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-017` e sincronizado no GitHub.

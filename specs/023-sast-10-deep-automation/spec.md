# Feature Specification: SDD Iteration 23 — Deep AL1 Automation & Academic Justification for Control SAST-10

**Feature Branch**: `023-sast-10-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 15/61: `SAST-10`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-10 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-10` (*"No dynamic code execution on untrusted input (`eval`, `Function`, `exec`, reflection)"*) utilize análise de fluxo de dados (`mode: taint` no Semgrep) a partir de entradas de requisição/usuário até `eval`, `new Function`, `safeEval`, `vm` e `child_process.exec` (e equivalentes em Python), eliminando falsos positivos em usos literais/estáticos.

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop e verificar que os 2 fluxos reais de RCE (`routes/b2bOrder.ts:21` e `routes/userProfile.ts:65`) são capturados sem os 3 falsos positivos anteriores (`routes/captcha.ts:22`, `lib/xml.ts:38`, `routes/fileUpload.ts:114`).

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE converter `CASA3-SAST-10-dynamic-code-execution` para `mode: taint` e adicionar `CASA3-SAST-10-dynamic-code-execution-python`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 15/61: SAST-10 (Iteração SDD 023)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-023` e sincronizado no GitHub.

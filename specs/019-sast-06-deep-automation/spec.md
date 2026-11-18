# Feature Specification: SDD Iteration 19 — Deep AL1 Automation & Academic Justification for Control SAST-06

**Feature Branch**: `019-sast-06-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 11/61: `SAST-06`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-06 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-06` (*"All security-relevant randomness uses a CSPRNG"*) utilize análise de fluxo de dados (`mode: taint` no Semgrep) a partir de fontes não-CSPRNG (`Math.random()`, `Date.now()`, `new Date()`, `random.*`) até sorvedouros críticos de segurança (segredos JWT, CAPTCHA, tokens, IVs, salts e senhas), eliminando falsos positivos em dados benignos.

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop e verificar que os 7 caminhos reais de Taint (`lib/insecurity.ts:53`, `routes/b2bOrder.ts:41` e `routes/captcha.ts:14-19`) são reportados sem os 3 falsos positivos anteriores de catálogo (`quantity`, `price`, `eta`).

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE converter `CASA3-SAST-06-insecure-randomness` para `mode: taint` e adicionar `CASA3-SAST-06-insecure-randomness-python`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 11/61: SAST-06 (Iteração SDD 019)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-019` e sincronizado no GitHub.

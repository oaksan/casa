# Feature Specification: SDD Iteration 24 — Deep AL1 Automation & Academic Justification for Control SAST-11

**Feature Branch**: `024-sast-11-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 16/61: `SAST-11`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-11 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-11` (*"File paths are not constructed from unvalidated user-supplied metadata"*) execute análise de fluxo de dados (`mode: taint` no Semgrep) a partir de parâmetros de requisição, nomes de arquivos enviados e entradas de arquivos compactados (`entry.path` — Zip Slip) até APIs de sistema de arquivos (`res.sendFile`, `fs.createWriteStream`, `fs.readFileSync`, `path.resolve`), com suporte a sanitizadores (`path.basename`, `sanitizeFilename`) e equivalente Python.

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop e verificar que os 10 achados reais (incluindo Zip Slip em `routes/fileUpload.ts:31, 34`, LFR em `routes/dataErasure.ts:104` e Path Traversal em `fileServer.ts:32`, `keyServer.ts:14`, `logfileServer.ts:14`, `quarantineServer.ts:14`) são reportados em `output/semgrep-sast.sarif`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE converter `CASA3-SAST-11-path-traversal` para `mode: taint` e adicionar `CASA3-SAST-11-path-traversal-python`.
- **FR-002**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 16/61: SAST-11 (Iteração SDD 024)`.
- **FR-003**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-024` e sincronizado no GitHub.

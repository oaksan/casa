# Feature Specification: SDD Iteration 22 — Deep AL1 Automation & Academic Justification for Control SAST-09

**Feature Branch**: `022-sast-09-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 14/61: `SAST-09`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-09 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-09` (*"Deserialization of untrusted data is avoided or integrity-protected"*) detecte todos os sinks reais de desserialização não confiável — incluindo `yaml.load(...)` passado em uploads via `vm.runInContext`, parsing XML com `XML_PARSE_NOENT | XML_PARSE_DTDLOAD` / `XmlDocument.fromString`, `serialize.unserialize` e desserializadores inseguros em Python (`pickle`, `marshal`, `yaml.load`, `jsonpickle`).

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop e verificar que os 8 achados deduplicados (incluindo `routes/fileUpload.ts:80, 114` e `lib/xml.ts:35, 38`) são reportados e gravados em `output/semgrep-sast.sarif`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE expandir `CASA3-SAST-09-unsafe-deserialization` e adicionar `CASA3-SAST-09-unsafe-deserialization-python`.
- **FR-002**: `run_sast_checks()` em `casa-assessment/casa_audit/scanner.py` DEVE deduplicar resultados Semgrep por `(sid, rel_p, line_no)`.
- **FR-003**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 14/61: SAST-09 (Iteração SDD 022)`.
- **FR-004**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-022` e sincronizado no GitHub.

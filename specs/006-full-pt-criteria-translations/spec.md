# Feature Specification: Iteration 6 — Complete PT-BR Translation of All 76 PASS/FAIL Criteria, Procedures & AL2 Checklists + Automated Rollback ZIP Archive

**Feature Branch**: `[006-full-pt-criteria-translations]`

**Created**: 2026-11-18

**Status**: Implemented (Iteration 6)

**Input**: User description: "implemente a iteracao 6 sdd para traduzir corretamente na aba Relatório a parte de Critério de PASS Exigido para Correção de todos os controles. Exemplo abaixo que está errado. 'Critério de PASS Exigido para Correção: Zero achados com CVSS v3.1 base ≥ 7.0 and whose vulnerable symbol is call-graph reachable, and zero components matching a CISA KEV identifier.' De agora em diante, para cada nova iteracao aproveite para comprimir em formato zip a pasta do projeto /home/user/felipe/speckit/casa com uma referencia para o numero da iteracao para facilitar algum possível rollback. por exemplo, ao final desta iteracao eu espero que seja gerado o arquivo: /home/user/felipe/speckit/casa-006.zip."

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - 100% Native PT-BR PASS/FAIL Criteria and Procedures in Report & Assessment Views (Priority: P1)

As a researcher or assessor viewing the CASA 3.0 Assessment and Report tabs in **Português (Brasil)** (`PT`), I want the **Critério de PASS Exigido para Correção** (`pass_criteria_pt`), **Sinal de FAIL** (`fail_criteria_pt`), **Procedimento de Teste** (`procedure_items_pt`), and **Evidências de verificação** (`verification_checklist_pt`) of all **76 controls** to be 100% translated into fluent technical Brazilian Portuguese — with zero mixed English phrases — so that the generated report and UI are publication-ready for the Master's dissertation.

**Why this priority**: Partial string replacement in Iteration 4 left mixed English clauses in `pass_criteria_pt` (e.g., `SCA-01`). Explicit per-control translations for all 76 controls ensure complete linguistic and technical accuracy.

**Independent Test**: Select `PT` in the topbar, run the scan or switch to the **Relatório** tab, and verify that **Critério de PASS Exigido para Correção** and the specification details on every control card are 100% in Brazilian Portuguese.

**Acceptance Scenarios**:

1. **Given** the UI language is set to `PT`, **When** viewing `SCA-01` in the Report or Assessment view, **Then** its PASS criterion reads: *"Zero achados com CVSS v3.1 base ≥ 7.0 cujo símbolo vulnerável seja alcançável no grafo de chamadas (call-graph), e zero componentes presentes no catálogo CISA KEV."*
2. **Given** all 76 controls in `casa3_controls.json`, **When** inspected by automated tests, **Then** every single control has dedicated, complete `pass_criteria_pt`, `fail_criteria_pt`, `procedure_items_pt`, and `verification_checklist_pt` without untranslated English clauses.

---

### User Story 2 - Per-Iteration Rollback ZIP Archive & GitHub Upload (Priority: P1)

As the project owner, I want every SDD iteration from Iteration 6 onwards to automatically generate a versioned ZIP archive `/home/user/felipe/speckit/casa-NNN.zip` (e.g., `/home/user/felipe/speckit/casa-006.zip`) alongside pushing the commit to `https://github.com/oaksan/casa`, so that I have an immediate local rollback snapshot for every SDD milestone.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-601**: `casa-assessment/scripts/pt_translations.py` MUST provide explicit dictionaries (`PASS_CRITERIA_PT`, `FAIL_CRITERIA_PT`, `PROCEDURES_PT`) for all **76 CASA 3.0 controls** (`SCA-01..05`, `SAST-01..14`, `TLS-01..06`, `CFG-01..11`, `AUT-01..12`, `AZI-01..13`, `OAU-01..11`, `WHK-01..04`).
- **FR-602**: `build_casa3_data.py` MUST compile these complete PT-BR translations into `casa-assessment/data/casa3_controls.json` and `casa-assessment/frontend/data.js`, including fully translated `verification_checklist_pt` items for all 76 controls.
- **FR-603**: `test_iteration1.py` MUST assert that no untranslated English sentences remain in `pass_criteria_pt`, `fail_criteria_pt`, `procedure_items_pt`, or `verification_checklist_pt` across all 76 controls.
- **FR-604**: At the conclusion of Iteration 6 (and every subsequent SDD iteration `NNN`), the project directory `/home/user/felipe/speckit/casa` MUST be compressed to `/home/user/felipe/speckit/casa-NNN.zip` and pushed to `https://github.com/oaksan/casa`.

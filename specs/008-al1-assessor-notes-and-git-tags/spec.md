# Feature Specification: Iteration 8 — AL1 Assessor Notes Label Refinement & Git Tag Versioning Policy

**Feature Branch**: `[008-al1-assessor-notes-and-git-tags]`

**Created**: 2026-11-18

**Status**: Implemented (Iteration 8)

**Input**: User description: "OK, concordo. a partir da proxima iteracao use a estrategia: 3. A melhor prática: Usar Git Tags em vez de .zip local. implemente a iteracao 8 sdd, com base no anexo, para todos controles AL1 passando de 'Triagem do Avaliador / Notas de Evidência Automatizada' para 'Notas do Avaliador' e de 'Caminhos de artefatos ...' para 'Notas como controles compensatórios'"

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Clearer AL1 Assessor Notes Label and Placeholder (Priority: P1)

As an assessor reviewing automated AL1 control results, I want the notes field label on all AL1 controls to read **"Notas do Avaliador"** (EN: **"Assessor Notes"**) and its placeholder to read **"Notas como controles compensatórios"** (EN: **"Notes such as compensating controls"**), so that the field is concise and aligned with the removal of manual artifact path entry.

**Why this priority**: Improves UI clarity and removes obsolete references to manual SARIF/CycloneDX/HAR path entry removed in Iteration 5.

**Independent Test**: Run or view any evaluated AL1 control in `assess.html` in `PT`, and verify the label reads `Notas do Avaliador` and the placeholder reads `Notas como controles compensatórios`.

**Acceptance Scenarios**:

1. **Given** an evaluated AL1 control card in `PT`, **When** the detail block is rendered, **Then** the notes label is `"Notas do Avaliador"` and the textarea placeholder is `"Notas como controles compensatórios"`.
2. **Given** an evaluated AL1 control card in `EN`, **When** the detail block is rendered, **Then** the notes label is `"Assessor Notes"` and the textarea placeholder is `"Notes such as compensating controls"`.

---

### User Story 2 - Git Tag Versioning Strategy Replacing Local ZIP Backups (Priority: P1)

As the project owner, I want each SDD iteration `NNN` to be versioned via a Git commit and an annotated/lightweight Git tag (`sdd-NNN`) pushed to `https://github.com/oaksan/casa` (`git push origin main --tags`) instead of generating large local `.zip` archives.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-801**: Update `I18N.pt.triageNotesLbl` to `"Notas do Avaliador"` and `I18N.pt.triageNotesPh` to `"Notas como controles compensatórios"` in `casa-assessment/frontend/app.js`.
- **FR-802**: Update `I18N.en.triageNotesLbl` to `"Assessor Notes"` and `I18N.en.triageNotesPh` to `"Notes such as compensating controls"` in `casa-assessment/frontend/app.js`.
- **FR-803**: Amend `.specify/memory/constitution.md` (`v1.4.0`) to replace local `.zip` generation with Git Tags (`sdd-NNN`) pushed to `https://github.com/oaksan/casa`.

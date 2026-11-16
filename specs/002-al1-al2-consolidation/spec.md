# Feature Specification: Iteration 2 — Consolidation of CASA 3.0 Assurance Levels into AL1 (61 Automated) and AL2 (+15 Lab-Adjudicated)

**Feature Branch**: `[002-al1-al2-consolidation]`

**Created**: 2026-11-16

**Status**: Implemented (Iteration 2)

**Input**: User description: "crie uma nova iteracao sdd removendo as referencias para AL0 (vamos considerar os 61 controles como sendo AL1) e faça o upload ao final para https://github.com/oaksan/casa."

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Two-Tier CASA 3.0 Assurance Model (AL1 & AL2 Only) (Priority: P1)

As a security researcher or assessor using the CASA 3.0 assessment platform, I want the framework, UI, scanner engine, reports, and SDD documentation to treat the **61 deterministic controls exclusively as AL1** (`AL1 — Automated Assessment`) and the **full 76-control set as AL2** (`AL2 — Full Lab Assessment: 61 AL1 + 15 AL2`), with all redundant references to `AL0` removed, so that the methodology and tool reflect a clear, unambiguous two-layer verification architecture.

**Why this priority**: Eliminates administrative redundancy between AL0 and AL1 (which share the exact same 61 technical controls in CASA 3.0) and sharpens the Master's thesis methodology into two distinct technical tiers: automated verification (**AL1**) vs. human lab adjudication (**AL2**).

**Independent Test**: Inspect the Target Assurance Level selector, control badges, progress bar, compliance report cards, JSON export, and SDD documentation, and verify that only `AL1` (61 automated controls) and `AL2` (61 AL1 + 15 AL2 = 76 controls) are presented, with zero references to `AL0`.

**Acceptance Scenarios**:

1. **Given** the CASA 3.0 Assessment UI (`assess.html`), **When** the user opens the **Target Assurance Level** dropdown, **Then** only `AL1 — Automated Assessment (61 Controls)` and `AL2 — Full Lab Assessment (61 AL1 + 15 AL2)` are available.
2. **Given** any of the 61 deterministic controls in the UI or exported JSON report, **When** its tier badge and report KPI card are rendered, **Then** it is labeled `AL1 · Automated` (and `AL1 Automated (PASS/NA)` in the report).
3. **Given** the project repository (`casa-assessment/`, `.specify/`, `specs/`), **When** searched for `AL0` references, **Then** zero occurrences remain in the active codebase, UI, API contracts, and SDD specifications.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-201**: System MUST define exactly two assurance levels in `casa3_controls.json` and `data.js`: `AL1` (61 deterministic automated controls) and `AL2` (61 automated AL1 controls + 15 manual lab-adjudicated AL2 controls = 76 total).
- **FR-202**: Frontend (`assess.html`, `app.js`, `styles.css`), scanner (`scanner.py`), API contract (`openapi.json`), and documentation (`README.md`, `.specify/memory/constitution.md`, `specs/`) MUST reference only `AL1` and `AL2`, removing all mentions of `AL0`.
- **FR-203**: Automated verification test suite (`test_iteration1.py`) MUST assert that `assurance_levels` in `casa3_controls.json` contains exclusively `["AL1", "AL2"]` and that no `AL0` strings exist in the frontend or dataset.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-201**: `casa3_controls.json` and `window.CASA3_DATA.assurance_levels` contain exclusively `AL1` and `AL2`.
- **SC-202**: Automated tests confirm zero occurrences of `AL0` across `casa-assessment/` and `.specify/` / `specs/`.
- **SC-203**: All changes are committed and pushed to `https://github.com/oaksan/casa`.

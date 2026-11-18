# Feature Specification: Iteration 4 — Bilingual Frontend Toggle (PT-BR / EN)

**Feature Branch**: `[004-i18n-pt-en]`

**Created**: 2026-11-18

**Status**: Implemented (Iteration 4)

**Input**: User description: "implemente a iteracao 4 sdd com um botao de exibicao do front end em PT (portugues brasil) ou EN (english)"

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Instant PT-BR / EN Language Switcher in Topbar (Priority: P1)

As a Brazilian researcher, developer, or security assessor using the ADA CASA 3.0 Assessment platform, I want a segmented **`PT | EN`** toggle button in the top navigation bar so that I can switch the entire interface, domain names, 76 control descriptions, pass/fail criteria, AL2 verification evidence checklists, and generated compliance reports between **Português (Brasil)** and **English** at any time without losing assessment state.

**Why this priority**: Essential for presenting and validating the tool both in a Brazilian Master's dissertation (PT-BR) and in international/ADA contexts (EN).

**Independent Test**: Open `assess.html`, click `PT` in the topbar, verify that all UI labels, the 8 domain names, the 76 control titles, pass/fail criteria, AL2 verification checklists, and the Report view switch immediately to Portuguese; click `EN` and verify everything switches back to English.

**Acceptance Scenarios**:

1. **Given** the user is on the Assessment or Report view, **When** they click `PT` in the topbar language switcher, **Then** all static labels, domain navigation items, control titles, pass/fail criteria, test procedures, AL2 verification checklists, and report summaries render in Brazilian Portuguese (`pt-BR`) and the preference is saved in `localStorage`.
2. **Given** the user is viewing the application in `PT`, **When** they click `EN` in the topbar language switcher, **Then** the entire UI and all 76 controls render in the canonical English text of the ADA CASA 3.0 specification.
3. **Given** an in-progress assessment with verdicts, automated scan logs, checklist ticks, notes, and screenshots, **When** the user toggles between `PT` and `EN`, **Then** zero assessment data is lost.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-401**: Topbar in `assess.html` MUST include a segmented language switcher (`PT` / `EN`) with `aria-pressed` state and `localStorage` persistence (`state.meta.lang`).
- **FR-402**: Specification compiler (`build_casa3_data.py`) MUST enrich `casa3_controls.json` and `frontend/data.js` with Brazilian Portuguese translations (`domain_pt`, `title_pt`, `pass_criteria_pt`, `fail_criteria_pt`, `evidence_items_pt`, `procedure_items_pt`, `verification_checklist_pt`) for all 76 CASA 3.0 controls (61 AL1 + 15 AL2) and 8 domains.
- **FR-403**: Frontend (`app.js`, `styles.css`) MUST dynamically translate all static and dynamic UI elements in both `#view-assess` and `#view-report` when `PT` or `EN` is selected.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-401**: 100% of the 76 controls and 8 domains have both English (`EN`) and Brazilian Portuguese (`PT`) fields in `casa3_controls.json` and `data.js`.
- **SC-402**: Toggling `PT` / `EN` updates both `#view-assess` and `#view-report` in `< 50ms` with zero data loss.
- **SC-403**: Automated unit tests in `test_iteration1.py` verify bilingual dataset completeness and UI toggle presence, and all changes are pushed to `https://github.com/oaksan/casa`.

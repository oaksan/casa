---
description: "Task list for Iteration 1: CASA 3.0 Web Application Assessment Tool"
---

# Tasks: Iteration 1 — CASA 3.0 Web Application Assessment Tool

**Input**: Design documents from `/specs/001-casa3-assessment/`

**Prerequisites**: [plan.md](file:///home/user/felipe/speckit/casa/specs/001-casa3-assessment/plan.md), [spec.md](file:///home/user/felipe/speckit/casa/specs/001-casa3-assessment/spec.md)

## Phase 1: Setup & Specification Import

- [x] T001 Import official `appdefensealliance/ASA-WG` repository (`CASA 2.1.1` and `CASA 3.0` specifications and test guides) into `CASA/`
- [x] T002 Ratify project constitution in `.specify/memory/constitution.md`
- [x] T003 Initialize `casa-assessment/` package structure (`scripts/`, `data/`, `casa_audit/`, `frontend/`, `tests/`)

---

## Phase 2: Foundational (CASA 3.0 Data Compiler)

- [x] T004 Implement CASA 3.0 Markdown specification & test guide parser in `casa-assessment/scripts/build_casa3_data.py`
- [x] T005 Generate `casa-assessment/data/casa3_controls.json` and `casa-assessment/frontend/data.js` with all 76 controls (61 AL1 + 15 AL2) across the 8 domains

---

## Phase 3: User Story 1 - Automated AL0 & AL1 Assessment Engine (Priority: P1) 🎯 MVP

- [x] T006 [US1] Implement repository SCA/SAST/Secret scanner and live URL TLS/Header/Cookie probe engine in `casa-assessment/casa_audit/scanner.py`
- [x] T007 [US1] Implement HTTP server with `GET /api/controls` and `POST /api/scan` in `casa-assessment/casa_audit/server.py`
- [x] T008 [US1] Implement AL0/AL1 automated execution panel, surface scoping (`Web_Application`, `Mobile`, `Native`), and client-side SARIF 2.1.0 / CycloneDX SBOM / W3C HAR 1.2 ingestion in `casa-assessment/frontend/assess.html` and `casa-assessment/frontend/app.js`

---

## Phase 4: User Story 2 - AL2 Interactive Workbench (DSOVS Style) (Priority: P1)

- [x] T009 [US2] Implement AL2 control cards with interactive `Verification evidence` checklists, `Notes` textareas, and `IndexedDB` drag-and-drop `Evidence screenshots` in `casa-assessment/frontend/app.js`
- [x] T010 [US2] Style control cards, verdict segmented buttons (`PASS`, `FAIL`, `N/A`, `N/C`), left domain rail, and sticky progress/filter bar in `casa-assessment/frontend/styles.css`

---

## Phase 5: User Story 3 - CASA 3.0 Compliance Report & Export (Priority: P2)

- [x] T011 [US3] Implement CASA 3.0 Compliance Report view (`#view-report`) with certification status badge, 4 KPI cards, dependency-free SVG Donut & 8-Axis Radar charts, and 8-Domain pipeline bar in `casa-assessment/frontend/app.js`
- [x] T012 [US3] Implement prioritized blocking remediation findings (`FAIL` & `Not_Covered`), numbered screenshot evidence gallery (`Figure 1..N`), JSON export, and Print/PDF stylesheet

---

## Phase 6: Verification & Automated Tests

- [x] T013 Write and execute automated verification tests for dataset completeness (61 AL1 + 15 AL2), scanner execution, and HTTP API in `casa-assessment/tests/test_iteration1.py`

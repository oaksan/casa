---
description: "Task list for Iteration 2: AL1 & AL2 Consolidation (Removing AL0)"
---

# Tasks: Iteration 2 — Consolidation of CASA 3.0 into AL1 (61 Controls) & AL2 (+15 Controls)

**Input**: Design documents from `/specs/002-al1-al2-consolidation/`

**Prerequisites**: [plan.md](file:///home/user/felipe/speckit/casa/specs/002-al1-al2-consolidation/plan.md), [spec.md](file:///home/user/felipe/speckit/casa/specs/002-al1-al2-consolidation/spec.md)

## Phase 1: SDD Governance & Specification Update

- [x] T201 Amend `.specify/memory/constitution.md` (v1.1.0) to standardize on two technical assurance levels (`AL1` Automated and `AL2` Lab-Adjudicated)
- [x] T202 Create Iteration 2 SDD artifacts in `specs/002-al1-al2-consolidation/` (`spec.md`, `plan.md`, `tasks.md`) and align `specs/001-casa3-assessment/`

---

## Phase 2: Codebase & Frontend Consolidation (`casa-assessment/`)

- [x] T203 Remove `AL0` from `assurance_levels` in `casa-assessment/scripts/build_casa3_data.py` and regenerate `casa3_controls.json` and `frontend/data.js`
- [x] T204 Remove all `AL0` labels and comments from `casa-assessment/frontend/assess.html`, `casa-assessment/frontend/app.js`, `casa-assessment/frontend/styles.css`, `casa-assessment/casa_audit/scanner.py`, and `casa-assessment/README.md`

---

## Phase 3: Verification & GitHub Upload

- [x] T205 Add unit test assertion in `casa-assessment/tests/test_iteration1.py` verifying that only `AL1` and `AL2` assurance levels exist and zero `AL0` references remain in `casa-assessment/`
- [x] T206 Commit Iteration 2 changes and push to `https://github.com/oaksan/casa`

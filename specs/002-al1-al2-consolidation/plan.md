# Implementation Plan: Iteration 2 — Consolidation of CASA 3.0 into AL1 & AL2

**Branch**: `[002-al1-al2-consolidation]` | **Date**: 2026-11-16 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/002-al1-al2-consolidation/spec.md)

**Input**: Feature specification from `/specs/002-al1-al2-consolidation/spec.md`

## Summary

Remove all references to `AL0` across the SDD documentation, data compiler, scanner engine, and OWASP DSOVS-inspired assessment frontend, consolidating the CASA 3.0 model into its two distinct technical verification tiers:
- **AL1 (61 Controls)**: 100% deterministic automated assessment over open evidence formats (`SARIF 2.1.0`, `CycloneDX 1.5`, `W3C HAR 1.2`).
- **AL2 (76 Controls = 61 AL1 + 15 AL2)**: Automated AL1 baseline plus 15 interactive lab-adjudicated controls with **Verification evidence** checklists, **Notes**, and **Evidence screenshots** (`IndexedDB`).

## Technical Context

**Language/Version**: Python 3.13+ & Vanilla ES6 JavaScript / HTML5 / CSS3

**Files Modified**:
- `.specify/memory/constitution.md` (Amended to v1.1.0 — AL1 & AL2 architecture)
- `casa-assessment/scripts/build_casa3_data.py` & generated `data/casa3_controls.json`, `frontend/data.js`
- `casa-assessment/frontend/assess.html`, `casa-assessment/frontend/app.js`, `casa-assessment/frontend/styles.css`
- `casa-assessment/casa_audit/scanner.py` & `casa-assessment/README.md`
- `specs/001-casa3-assessment/*` & `specs/002-al1-al2-consolidation/*`
- `casa-assessment/tests/test_iteration1.py` (Added test assertion verifying `assurance_levels == ["AL1", "AL2"]` and zero `AL0` references)

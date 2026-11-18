# Implementation Plan: Iteration 4 — Bilingual Frontend Toggle (PT-BR / EN)

**Branch**: `[004-i18n-pt-en]` | **Date**: 2026-11-18 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/004-i18n-pt-en/spec.md)

## Summary

Add a segmented **`PT | EN`** language switcher in the topbar of [`assess.html`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/assess.html) and provide full bilingual (`pt-BR` and `en`) support across:
1. [`casa-assessment/scripts/build_casa3_data.py`](file:///home/user/felipe/speckit/casa/casa-assessment/scripts/build_casa3_data.py) and [`casa-assessment/scripts/pt_translations.py`](file:///home/user/felipe/speckit/casa/casa-assessment/scripts/pt_translations.py): Compiles Portuguese translations for the 8 domains, assurance levels, and all 76 CASA 3.0 controls (`title_pt`, `pass_criteria_pt`, `fail_criteria_pt`, `evidence_items_pt`, `procedure_items_pt`, `verification_checklist_pt`).
2. [`casa-assessment/frontend/assess.html`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/assess.html), [`styles.css`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/styles.css), and [`app.js`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/app.js): Segmented `PT | EN` button in `.top-right` + complete `I18N` dictionary for Assessment and Report views.
3. [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py): Automated tests verifying bilingual fields on all 76 controls and language toggle presence in `assess.html`.

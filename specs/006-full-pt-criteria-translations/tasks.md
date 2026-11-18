---
description: "Task list for Iteration 6: Complete PT-BR Translation of All 76 Controls & Rollback ZIP"
---

# Tasks: Iteration 6 — Complete PT-BR Translation & Rollback ZIP

- [x] T601 Create SDD Iteration 6 documentation (`spec.md`, `plan.md`, `tasks.md`) in `specs/006-full-pt-criteria-translations/` and amend `.specify/memory/constitution.md` with the mandatory `casa-NNN.zip` + GitHub upload rule
- [x] T602 Write complete PT-BR translations for `PASS_CRITERIA_PT`, `FAIL_CRITERIA_PT`, and `PROCEDURES_PT` for all 76 controls in `casa-assessment/scripts/pt_translations.py`
- [x] T603 Update `casa-assessment/scripts/build_casa3_data.py` to build `pass_criteria_pt`, `fail_criteria_pt`, `procedure_items_pt`, and `verification_checklist_pt` from the complete dictionaries and regenerate `casa3_controls.json` & `data.js`
- [x] T604 Add unit test assertions in `casa-assessment/tests/test_iteration1.py` verifying zero English leftover clauses in `pass_criteria_pt` and `fail_criteria_pt` across all 76 controls
- [x] T605 Commit and push Iteration 6 to `https://github.com/oaksan/casa` and generate `/home/user/felipe/speckit/casa-006.zip`

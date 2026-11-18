---
description: "Task list for Iteration 4: Bilingual Frontend Toggle (PT-BR / EN)"
---

# Tasks: Iteration 4 — Bilingual Frontend Toggle (PT-BR / EN)

- [x] T401 Create SDD Iteration 4 specification (`spec.md`, `plan.md`, `tasks.md`) in `specs/004-i18n-pt-en/`
- [x] T402 Implement PT-BR technical translation module in `casa-assessment/scripts/pt_translations.py` and integrate into `casa-assessment/scripts/build_casa3_data.py`
- [x] T403 Regenerate `casa-assessment/data/casa3_controls.json` and `casa-assessment/frontend/data.js` with bilingual fields for all 76 controls and 8 domains
- [x] T404 Add segmented `PT | EN` toggle button in `casa-assessment/frontend/assess.html` and `.lang-switch` styling in `casa-assessment/frontend/styles.css`
- [x] T405 Implement reactive `PT` / `EN` i18n rendering for all UI labels, domains, 76 control cards, AL2 checklists, and Report view in `casa-assessment/frontend/app.js`
- [x] T406 Add bilingual verification tests in `casa-assessment/tests/test_iteration1.py`, run test suite, and push Iteration 4 to `https://github.com/oaksan/casa`

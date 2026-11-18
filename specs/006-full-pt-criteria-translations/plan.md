# Implementation Plan: Iteration 6 — Complete PT-BR Translation of All 76 Controls & Rollback ZIP Snapshot

**Branch**: `[006-full-pt-criteria-translations]` | **Date**: 2026-11-18 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/006-full-pt-criteria-translations/spec.md)

## Summary

1. Replace partial phrase replacement in [`casa-assessment/scripts/pt_translations.py`](file:///home/user/felipe/speckit/casa/casa-assessment/scripts/pt_translations.py) with complete, human-grade Brazilian Portuguese dictionaries (`PASS_CRITERIA_PT`, `FAIL_CRITERIA_PT`, `PROCEDURES_PT`) covering all **76 CASA 3.0 controls**.
2. Regenerate [`casa-assessment/data/casa3_controls.json`](file:///home/user/felipe/speckit/casa/casa-assessment/data/casa3_controls.json) and [`casa-assessment/frontend/data.js`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/data.js).
3. Add strict translation verification tests in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py).
4. Record the mandatory GitHub push + `/home/user/felipe/speckit/casa-NNN.zip` snapshot rule in [`.specify/memory/constitution.md`](file:///home/user/felipe/speckit/casa/.specify/memory/constitution.md), push to `https://github.com/oaksan/casa`, and generate `/home/user/felipe/speckit/casa-006.zip`.

# Implementation Plan: Iteration 8 — AL1 Assessor Notes Refinement & Git Tag Versioning

**Branch**: `[008-al1-assessor-notes-and-git-tags]` | **Date**: 2026-11-18 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/008-al1-assessor-notes-and-git-tags/spec.md)

## Summary

1. Update `triageNotesLbl` and `triageNotesPh` in [`casa-assessment/frontend/app.js`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/app.js) for both `PT` (`"Notas do Avaliador"` / `"Notas como controles compensatórios"`) and `EN` (`"Assessor Notes"` / `"Notes such as compensating controls"`).
2. Amend [`.specify/memory/constitution.md`](file:///home/user/felipe/speckit/casa/.specify/memory/constitution.md) (`v1.4.0`) to adopt Git Tags (`sdd-NNN`) pushed to `https://github.com/oaksan/casa` at the end of every SDD iteration.
3. Add verification assertions in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py), commit, create tag `sdd-008`, and push `main` and `--tags` to GitHub.

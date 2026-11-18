# Implementation Plan: Iteration 5 — Streamline AL1 Automation Panel

**Branch**: `[005-simplify-al1-controls]` | **Date**: 2026-11-18 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/005-simplify-al1-controls/spec.md)

## Summary

Remove the `Importar Evidências (SARIF / SBOM / HAR)` and `⚡ Carregar Execução Benchmark AL1` buttons from [`assess.html`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/assess.html) and [`app.js`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/app.js), leaving `▶ Executar Scan Automatizado AL1` (`▶ Run Automated AL1 Scan`) as the sole action in the AL1 Automation Panel.

## Files Modified
- `specs/005-simplify-al1-controls/spec.md`, `plan.md`, `tasks.md`
- `casa-assessment/frontend/assess.html`
- `casa-assessment/frontend/app.js`
- `casa-assessment/tests/test_iteration1.py`

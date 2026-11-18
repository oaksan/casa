# Feature Specification: Iteration 5 — Streamline AL1 Automation Panel (Single Real Scan Action)

**Feature Branch**: `[005-simplify-al1-controls]`

**Created**: 2026-11-18

**Status**: Implemented (Iteration 5)

**Input**: User description: "implemente a iteracao 5 sdd para remover os botoes: Importar Evidências (SARIF / SBOM / HAR) e ⚡ Carregar Execução Benchmark AL1"

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Single Unambiguous AL1 Automated Scan Action (Priority: P1)

As an assessor evaluating a web application in the CASA 3.0 interface, I want the AL1 Automation Panel to display only the real **`▶ Executar Scan Automatizado AL1`** (`▶ Run Automated AL1 Scan`) button — without the `Importar Evidências (SARIF / SBOM / HAR)` or `⚡ Carregar Execução Benchmark AL1` buttons — so that the workflow is focused exclusively on executing the real automated AL1 scanner against the target URL and source repository.

**Why this priority**: Prevents confusion between simulated benchmark data and real tool execution (`Semgrep` AST + `OSV.dev` + active HTTP/DAST probes) and simplifies the UI.

**Independent Test**: Open `assess.html`, inspect the AL1 Automation Panel, and verify that only `▶ Executar Scan Automatizado AL1` (`#btn-run-auto`) and the live status indicator are present.

**Acceptance Scenarios**:

1. **Given** the user opens `assess.html` in `PT` or `EN`, **When** viewing the AL1 Automation Panel (`.auto-actions`), **Then** only the `#btn-run-auto` button and `#auto-status` label are rendered (`#btn-demo-auto` and `#evidence-upload` are absent).
2. **Given** the user clicks `#btn-run-auto`, **When** the scan completes, **Then** all 61 AL1 controls are populated from the real `/api/scan` execution.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-501**: Remove `#i18n-btn-import-lbl` (`#evidence-upload`) and `#btn-demo-auto` buttons from `casa-assessment/frontend/assess.html`.
- **FR-502**: Remove the corresponding button handlers and unused i18n strings from `casa-assessment/frontend/app.js`, updating the panel heading and status message to reference exclusively the automated AL1 scan.
- **FR-503**: Update `casa-assessment/tests/test_iteration1.py` to assert that `btn-run-auto` is present and `btn-demo-auto` / `evidence-upload` are absent in `assess.html`.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-501**: `assess.html` contains neither `btn-demo-auto` nor `evidence-upload`.
- **SC-502**: All unit and integration tests pass and changes are pushed to `https://github.com/oaksan/casa`.

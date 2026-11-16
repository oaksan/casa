# Feature Specification: Iteration 1 — CASA 3.0 Web Application Assessment Tool (Automated AL1 + Interactive AL2 Workbench)

**Feature Branch**: `[001-casa3-assessment]`

**Created**: 2026-11-16

**Status**: Implemented (Iteration 1)

**Input**: User description: "crie entao a iteracao 1 do SDD para implementar o CASA 3. o front end do assesment será semelhante a: https://owasp.github.io/www-project-devsecops-verification-standard/assessment/assess.html, mas com base na lógica do CASA 3 (sendo automatizado a avaliação do AL0 e AL1 e o AL2 terá um checklist de Verification evidence, Notes e Evidence screenshot, conforme: https://owasp.github.io/www-project-devsecops-verification-standard/assessment/assess.html)"

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Automated AL1 Assessment and Open Evidence Ingestion (Priority: P1)

As a security lab assessor (**AL1**), I want to evaluate a web application against the **61 deterministic CASA 3.0 AL1 requirements** automatically (by running the automated scanner against a Target URL + Source Repository, or by importing open-format evidence files in SARIF 2.1.0, CycloneDX SBOM, and W3C HAR 1.2), so that all 61 AL1 controls receive objective `PASS`, `FAIL`, `NOT_APPLICABLE`, or `Not_Covered` verdicts with tool execution logs without manual questionnaires.

**Why this priority**: Core differentiator of CASA 3.0 over CASA 2.1.1; establishes the 61-control deterministic baseline required for AL1 and AL2.

**Independent Test**: Open `assess.html`, select `AL1`, click **Run Automated AL1 Scan** (or **Load Benchmark AL1 Run** / **Import Evidence**), and verify that all 61 AL1 controls across the 8 domains are automatically populated with verdicts and expandable tool output logs.

**Acceptance Scenarios**:

1. **Given** an assessment with Target Assurance Level set to `AL1`, **When** the user views the control list, **Then** only the 61 automated AL1 controls across the 8 CASA 3.0 domains (`SCA`, `SAST`, `TLS`, `CFG`, `AUT`, `AZI`, `OAU`, `WHK`) are in scope.
2. **Given** declared application surfaces (e.g., `Web_Application` checked, `Mobile` and `Native` unchecked), **When** scoping is applied, **Then** controls exclusively targeting `Mobile, Native` (such as `OAU-05` and `OAU-06`) are automatically marked `NOT_APPLICABLE`.
3. **Given** a target URL and repository path (or uploaded `.sarif` / `.cdx.json` / `.har` files), **When** the user triggers the automated scan, **Then** each of the 61 AL1 controls displays its deterministic verdict (`PASS`, `FAIL`, `NOT_APPLICABLE`, or `Not_Covered`), the executing tool name, and the formatted evidence log.

---

### User Story 2 - AL2 Lab-Adjudicated Assessment with Verification Evidence Checklist, Notes & Screenshots (Priority: P1)

As a security lab assessor conducting an **AL2** evaluation, I want an interactive workbench modeled on the OWASP DSOVS `assess.html` interface for the **15 AL2 lab-adjudicated requirements** (`SAST-14`, `AUT-09..12`, `AZI-07..13`, `OAU-10..11`, `WHK-04`), where each AL2 control provides a **Verification evidence** checklist, a **Notes** textarea, and an **Evidence screenshots** drag-and-drop uploader stored locally in the browser (`IndexedDB`), so that human-adjudicated tests are rigorously documented alongside the automated AL1 baseline.

**Why this priority**: Directly fulfills the hybrid CASA 3.0 AL2 model (61 automated AL1 controls + 15 interactive AL2 controls with DSOVS-style checklist, notes, and screenshots).

**Independent Test**: Set Target Assurance Level to `AL2`, filter by `AL2 Manual Checklist (15)`, select a verdict on an AL2 control (e.g., `AZI-08` Cross-Tenant IDOR), check off items under **Verification evidence**, type assessor **Notes**, and attach an image under **Evidence screenshots**; reload the page and verify all state and screenshots persist via `localStorage` and `IndexedDB`.

**Acceptance Scenarios**:

1. **Given** Target Assurance Level is set to `AL2`, **When** the user views any of the 15 AL2 controls, **Then** the card renders the `AL2 · Lab-Adjudicated` badge, the 5-state verdict segmented bar (`–`, `PASS`, `FAIL`, `N/A`, `N/C`), the **Verification evidence** checkbox list derived from `CASA 3.0 (AL2) Test Guide.md`, the **Notes** textarea, and the **Evidence screenshots** uploader.
2. **Given** an AL2 control card, **When** the user drags and drops or selects an image file via `Add screenshot`, **Then** the image is resized client-side, stored in `IndexedDB` (`casa3-figures`), rendered as a thumbnail with a caption input (`Describe what this screenshot shows…`) and `Remove` action.

---

### User Story 3 - CASA 3.0 Compliance Report, Visual Analytics & Export (Priority: P2)

As a developer or lab assessor, I want to switch to the **Report** view to inspect the overall CASA 3.0 certification status (`IN COMPLIANCE`, `REMEDIATION REQUIRED`, or `ASSESSMENT INCOMPLETE`), SVG Donut and 8-Domain Radar charts, an 8-Domain compliance pipeline bar, prioritized blocking remediation findings (`FAIL` and `Not_Covered`), numbered screenshot figures (`Figure 1..N`), JSON export, and Print/PDF generation.

**Why this priority**: Transforms the assessment state into an actionable deliverable for certification submission and academic evaluation in the Master's thesis.

**Independent Test**: Switch to the **Report** tab after running an AL1 scan and attaching an AL2 screenshot, verify the KPI cards, Donut/Radar charts, blocking gap list, and numbered `Figure 1` rendering, and export the JSON report.

**Acceptance Scenarios**:

1. **Given** evaluated controls in scope, **When** the user clicks `Report` or `Generate CASA 3.0 Report →`, **Then** the view renders the certification badge, executive summary prose, 4 KPI cards (`Controls evaluated`, `Pass rate`, `AL1 Automated`, `AL2 Lab-Adjudicated`), Donut & Radar SVG charts, and the 8-Domain pipeline (`SCA` › `SAST` › `TLS` › `CFG` › `AUT` › `AZI` › `OAU` › `WHK`).
2. **Given** any control with verdict `FAIL` or `Not_Covered`, **When** the report is generated, **Then** the certification status is marked `REMEDIATION REQUIRED` and each blocking control is listed with its exact CASA 3.0 `PASS` criterion, reference open-source tooling, automated log, assessor notes, and figure references (`Figure 1..N`).

---

### Edge Cases

- **Unreachable Target URL during Live Scan**: Dynamic HTTP/TLS controls (`TLS-*`, `CFG-*`, etc.) are gracefully marked `Not_Covered` with the connection error logged, without crashing the static repository scan (`SCA-*`, `SAST-*`).
- **Undeclared Webhooks**: Following CASA 3.0 Domain 8 scoping rules, when no webhook receiver or callback facility is declared, `WHK-01..03` default to `Not_Covered` rather than false `PASS`.
- **Browser Offline / Static `file://` Execution**: If the local Python backend (`/api/scan`) is not running, the frontend remains 100% functional using client-side evidence ingestion (`.sarif`, `.json`, `.har`), benchmark simulation, `localStorage`, and `IndexedDB`.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST parse all **61 AL1 requirements** and **15 AL2 requirements** (76 total) across the 8 domains directly from `CASA/CASA 3.0 (AL1) Specification.md`, `CASA/CASA 3.0 (AL1) Test Guide.md`, `CASA/CASA 3.0 (AL2) Specification.md`, and `CASA/CASA 3.0 (AL2) Test Guide.md`.
- **FR-002**: Frontend MUST replicate the visual layout, sticky topbar, segmented `Assessment`/`Report` switcher, left domain rail with scroll-spy, sticky progress bar, and print stylesheet of the OWASP DSOVS `assess.html` application.
- **FR-003**: System MUST dynamically scope controls based on Target Assurance Level (`AL1` = 61 automated controls; `AL2` = 61 automated + 15 manual lab-adjudicated controls) and Declared Surfaces (`Web_Application`, `Mobile`, `Native`).
- **FR-004**: System MUST provide automated execution for AL1 controls via a Python scanner API (`POST /api/scan`) and client-side ingestion of open evidence files (`SARIF 2.1.0`, `CycloneDX/SPDX SBOM`, `W3C HAR 1.2`).
- **FR-005**: System MUST render an interactive **Verification evidence** checklist, **Notes** field, and **Evidence screenshots** uploader (backed by `IndexedDB`) for all 15 AL2 controls.
- **FR-006**: System MUST generate a visual Compliance Report with SVG Donut and 8-Axis Radar charts, domain pipeline bar, blocking remediation list, numbered screenshot gallery (`Figure 1..N`), JSON export, and Print/PDF support.

### Key Entities

- **`ControlSpec`**: Represents one of the 76 CASA 3.0 requirements (`id`, `domain`, `tier` [`AL1` | `AL2`], `automation` [`automated` | `lab_adjudicated`], `profile`, `reference`, `evidence_items`, `procedure_items`, `reference_tooling`, `pass_criteria`, `fail_criteria`, `verification_checklist`).
- **`ControlAssessmentState`**: Represents the current evaluation of a control (`verdict` [`PASS` | `FAIL` | `NOT_APPLICABLE` | `Not_Covered` | `null`], `autoTool`, `autoLog`, `autoTimestamp`, `evidence` checklist map, `notes`, `figures` list in `IndexedDB`).

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the **76 CASA 3.0 controls** (61 AL1 + 15 AL2) are present, accurately categorized into the 8 domains, and linked to their official PASS/FAIL criteria and reference open-source tooling.
- **SC-002**: Executing an automated AL1 run evaluates all 61 AL1 controls in under 5 seconds locally and populates deterministic verdicts and evidence logs.
- **SC-003**: All AL2 verification evidence checkboxes, notes, and attached screenshots survive browser reloads via `localStorage` and `IndexedDB` and render as numbered figures (`Figure 1..N`) in the printable report.

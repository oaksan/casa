# Implementation Plan: Iteration 1 — CASA 3.0 Web Application Assessment Tool

**Branch**: `[001-casa3-assessment]` | **Date**: 2026-11-16 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/001-casa3-assessment/spec.md)

**Input**: Feature specification from `/specs/001-casa3-assessment/spec.md`

## Summary

Deliver **Iteration 1** of the ADA CASA 3.0 Web Application Security Assessment tool (`casa-assessment/`), combining:
1. A specification parser ([`build_casa3_data.py`](file:///home/user/felipe/speckit/casa/casa-assessment/scripts/build_casa3_data.py)) that compiles the official CASA 3.0 AL1 (61 controls) and AL2 (15 controls) Markdown specifications and test guides into structured JSON/JS.
2. An OWASP DSOVS-inspired browser frontend ([`assess.html`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/assess.html), [`styles.css`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/styles.css), [`app.js`](file:///home/user/felipe/speckit/casa/casa-assessment/frontend/app.js)) that automates `AL1` assessment and provides interactive `Verification evidence` checklists, `Notes`, and `IndexedDB` `Evidence screenshots` for `AL2`.
3. A Python automated scanner and local web server ([`casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py), [`casa_audit/server.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/server.py)) that executes real repository and HTTP/TLS probes via `POST /api/scan`.

## Technical Context

**Language/Version**: Python 3.13+ (Backend/CLI/Parser) + Vanilla ES6 JavaScript, HTML5, CSS3 (Frontend)

**Primary Dependencies**: Zero external mandatory runtime dependencies (uses Python standard library `http.server`, `ssl`, `urllib`, `json`, `re`, `pathlib` + Browser `localStorage` and `IndexedDB`)

**Storage**: Browser `localStorage` (`casa3-assessment-v1`) for assessment metadata, verdicts, logs, checklists, and notes; Browser `IndexedDB` (`casa3-figures`) for resized screenshot evidence; JSON files on disk (`casa-assessment/data/casa3_controls.json`)

**Testing**: `pytest` / `unittest` for specification parser, automated AL1 scanner, and HTTP API endpoints

**Target Platform**: Linux / Cross-platform Web Browser

**Project Type**: Web application + CLI scanner (`casa-assessment/`)

**Performance Goals**: `< 100ms` UI view switching and filtering across all 76 controls; `< 5s` local automated AL1 baseline scan

**Constraints**: Offline-capable browser UI; zero proprietary scanner lock-in; strict adherence to CASA 3.0 verdict rules

**Scale/Scope**: 76 CASA 3.0 controls (61 AL1 automated + 15 AL2 lab-adjudicated) across 8 domains

## Constitution Check

- **I. Specification-Driven Truth**: Passed — `build_casa3_data.py` parses `CASA/CASA 3.0 (AL1|AL2) Specification.md` and `Test Guide.md` directly.
- **II. Deterministic Automation for AL1**: Passed — 61 AL1 controls evaluated via `/api/scan` and SARIF/SBOM/HAR ingestion.
- **III. DSOVS-Inspired Interactive Workbench for AL2**: Passed — 15 AL2 controls feature `Verification evidence` checkboxes, `Notes`, and `IndexedDB` `Evidence screenshots`.
- **IV. Open-Source First**: Passed — zero dependency on Burp Suite Pro.
- **V. Local-First Privacy & Reproducibility**: Passed — `localStorage` + `IndexedDB` + JSON export + print-ready PDF report.

## Project Structure

### Documentation (this feature)

```text
specs/001-casa3-assessment/
├── spec.md              # Feature specification (User Stories, FRs, SCs)
├── plan.md              # Technical implementation plan
└── tasks.md             # Iteration 1 task checklist & verification status
```

### Source Code (repository root)

```text
CASA/
├── CASA 3.0 (AL1) Specification.md
├── CASA 3.0 (AL1) Test Guide.md
├── CASA 3.0 (AL2) Specification.md
├── CASA 3.0 (AL2) Test Guide.md
├── CASA Specification.md
└── CASA Test Guide.md

casa-assessment/
├── README.md
├── data/
│   └── casa3_controls.json          # Compiled 76 CASA 3.0 controls (61 AL1 + 15 AL2)
├── scripts/
│   └── build_casa3_data.py          # Markdown-to-JSON/JS specification compiler
├── casa_audit/
│   ├── __init__.py
│   ├── __main__.py                  # CLI entry point (python3 -m casa_audit)
│   ├── scanner.py                   # Automated AL1 scanner (SCA, SAST, TLS, CFG, AUT, AZI, OAU, WHK)
│   └── server.py                    # HTTP server + /api/scan & /api/controls endpoints
├── frontend/
│   ├── assess.html                  # DSOVS-inspired CASA 3.0 assessment & report UI
│   ├── styles.css                   # Geist/Apple-clean responsive & print stylesheet
│   ├── data.js                      # Auto-generated window.CASA3_DATA bundle
│   └── app.js                       # State, AL1 automation, AL2 checklists/screenshots, SVG charts
└── tests/
    └── test_iteration1.py           # Automated verification suite for Iteration 1
```

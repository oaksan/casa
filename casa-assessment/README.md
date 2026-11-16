# ADA CASA 3.0 Assessment Tool (Iteration 1)

Interactive web application security assessment frontend and automated AL0/AL1 scanner engine based on the **App Defense Alliance CASA 3.0 Specification** (`AL0`, `AL1`, and `AL2`), inspired by the [OWASP DevSecOps Verification Standard (DSOVS) Assessment UI](https://owasp.github.io/www-project-devsecops-verification-standard/assessment/assess.html).

## Architecture & Features

1. **AL0 & AL1 Automated Assessment (61 Deterministic Controls across 8 Domains):**
   - **Live Automated Scan (`/api/scan`)**: Evaluates local source code / lockfiles (`SCA-01..05`, `SAST-01..13`) and live application URLs (`TLS-01..06`, `CFG-01..11`, `AUT-01..08`, `AZI-01..06`, `OAU-01..09`, `WHK-01..03`).
   - **Open Evidence Importer**: Directly ingests **OASIS SARIF 2.1.0** (`.sarif`, `.json`), **CycloneDX / SPDX SBOM** (`.json`), and **W3C HAR 1.2** (`.har`) in the browser.
   - **Surface Scoping**: Automatically marks controls outside declared surfaces (`Web_Application`, `Mobile`, `Native`) as `NOT_APPLICABLE`.

2. **AL2 Lab-Adjudicated Assessment (+15 Controls = 76 Total):**
   - Interactive **Verification evidence** checklist extracted from `CASA 3.0 (AL2) Test Guide.md`.
   - Assessor **Notes** field for triage context, test accounts, and caveats.
   - **Evidence screenshots** drag-and-drop & upload persisted locally in `IndexedDB`, with captions and automatic numbering (`Figure 1..N`) in the generated compliance report.

3. **CASA 3.0 Compliance Report View:**
   - Certification Status Badge (`IN COMPLIANCE`, `REMEDIATION REQUIRED`, `ASSESSMENT INCOMPLETE`).
   - Dependency-free SVG **Donut** and **8-Axis Domain Radar** charts + **8-Domain Pipeline** bar.
   - Prioritized blocking findings (`FAIL` and `Not_Covered`) with exact `PASS` criteria and reference open-source tooling.
   - **Export CASA 3.0 JSON** & **Print / Save PDF**.

## Quick Start

```bash
# 1. (Optional) Regenerate control dataset from CASA/CASA 3.0 (*.md) files
python3 casa-assessment/scripts/build_casa3_data.py

# 2. Start the Web UI & Automated Scanner Server on port 8080
PYTHONPATH=casa-assessment python3 -m casa_audit --port 8080
```

Then open **http://127.0.0.1:8080/assess.html** in your browser (or open `casa-assessment/frontend/assess.html` directly).

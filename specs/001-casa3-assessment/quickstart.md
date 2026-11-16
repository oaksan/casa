# Quickstart Guide: ADA CASA 3.0 Assessment Tool (Iteration 1)

**Feature**: `001-casa3-assessment` | **Date**: 2026-11-16

---

## 1. Starting the Assessment Web UI & Scanner API

From the repository root (`/home/user/felipe/speckit/casa`):

```bash
# Start the local web server and automated AL0/AL1 scanner API on port 8080
PYTHONPATH=casa-assessment python3 -m casa_audit --host 127.0.0.1 --port 8080
```

Open **http://127.0.0.1:8080/assess.html** in your browser.

---

## 2. Running an Assessment (3 Workflows)

### Workflow A: Automated AL0 / AL1 Scan (Live Repository + Target URL)
1. In the **Setup** card, enter the Application Name, Assessor Name, and select **Target Assurance Level** (`AL0`, `AL1`, or `AL2`).
2. Check the **Declared Surfaces** (`Web_Application`, `Mobile`, `Native`). Notice that controls outside declared surfaces (e.g., `OAU-05` and `OAU-06` when only `Web_Application` is selected) are automatically marked `NOT_APPLICABLE`.
3. Enter a **Target Application URL** (optional) and **Source Repository Path** (defaults to `/home/user/felipe/speckit/casa`) and click **`▶ Run Automated AL0/AL1 Scan`**.
4. All 61 AL1 controls are evaluated and populated with deterministic verdicts (`PASS`, `FAIL`, `NOT_APPLICABLE`, `Not_Covered`) and expandable tool logs.

### Workflow B: Ingesting Open Evidence Files (SARIF 2.1.0, CycloneDX SBOM, W3C HAR 1.2)
1. Click **`⇧ Import Evidence (SARIF / SBOM / HAR)`** in the Automation Panel.
2. Select one or more sample evidence files from [`casa-assessment/samples/`](file:///home/user/felipe/speckit/casa/casa-assessment/samples):
   - `sample-semgrep-sast.sarif` (populates `SAST-01..13` from OASIS SARIF 2.1.0 findings)
   - `sample-sbom.cdx.json` (populates `SCA-01, SCA-02, SCA-04, SCA-05` from CycloneDX 1.5 SBOM)
   - `sample-traffic.har` (populates `TLS-01` from W3C HAR 1.2 capture)

### Workflow C: Interactive AL2 Lab-Adjudicated Checklist & Screenshots
1. Set **Target Assurance Level** to `AL2` and click the filter pill **`AL2 Manual Checklist (15)`**.
2. For each of the 15 AL2 controls (`SAST-14`, `AUT-09..12`, `AZI-07..13`, `OAU-10..11`, `WHK-04`):
   - Select the verdict (`PASS`, `FAIL`, `N/A`, `N/C`).
   - Check off completed items under **Verification evidence**.
   - Record lab observations under **Notes**.
   - Drag and drop screenshots (or click **`Add screenshot`**) under **Evidence screenshots** and add captions.
3. Click **`Generate CASA 3.0 Report →`** (or the **`Report`** switch in the topbar) to view the compliance dashboard, Donut & Radar charts, blocking remediation roadmap, and numbered evidence figures (`Figure 1..N`), then click **`Export CASA 3.0 JSON`** or **`Print / Save PDF Report`**.

---

## 3. Running Automated Verification Tests

```bash
PYTHONPATH=casa-assessment python3 -m unittest discover -s casa-assessment/tests -v
```

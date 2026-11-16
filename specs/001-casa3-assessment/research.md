# Phase 0 Research: CASA 2.1.1 vs. CASA 3.0 & OWASP DSOVS UI Adaptation

**Feature**: `001-casa3-assessment` | **Date**: 2026-11-16

---

## 1. Evolution from CASA 2.1.1 to CASA 3.0

| Dimension | CASA 2.1.1 (`main` branch) | CASA 3.0 (`AL1` & `AL2` Specifications) |
| :--- | :--- | :--- |
| **Total Controls** | 55 controls across 7 sections (`1.1.1` – `7.3.2`) | **76 controls** across 8 domains (**61 AL1** + **15 AL2**) |
| **AL1 Execution Model** | *Verified Self-Assessment*: Developer fills out Excel questionnaire (`CASA AL1 Onboarding Questionnaire.xlsx`), writes free-text descriptions, and attaches screenshots | *Lab-Executed Automated Assessment* : 100% deterministic pass/fail criteria over open machine-readable evidence formats |
| **AL2 Execution Model** | *Lab Assessment*: Human lab tests all 55 controls using Burp Suite Pro + manual WSTG checks | *Full Lab Assessment*: All 61 automated AL1 controls **plus** 15 lab-adjudicated controls requiring human context (cross-tenant IDOR, privilege escalation, verifier lifecycle, admin MFA) |
| **Scanner Lock-in** | Mandates commercial **Burp Suite Professional** via `ADA Burp Audit Scan Configuration.json` | **Tool-agnostic & Open-Source ready**: explicitly lists `semgrep`, `gitleaks`, `syft`, `osv-scanner`, `trivy`, `testssl.sh`, `OWASP ZAP`, `nuclei`, `Playwright`, `mitmproxy` as reference tooling |
| **Evidence Formats** | Free-text spreadsheets (`.xlsx`), `.docx` reports, screenshots | **OASIS SARIF 2.1.0**, **CycloneDX 1.5 / SPDX 2.3 SBOM**, **W3C HAR 1.2** |

### Disposition of CASA 2.1.1 Controls in CASA 3.0
- **34 controls** carried forward into **AL1** with deterministic pass/fail criteria.
- **1 control** split between **AL1** (`SAST-06` CSPRNG randomness) and **AL2** (`AUT-11` out-of-band verifier lifecycle).
- **15 controls** elevated to **AL2** (requiring human adjudication / multi-role test accounts).
- **5 controls** retired (lacking deterministic testability).
- **30 new deterministic requirements** added to **AL1** (including software supply chain integrity `SCA-01..05`, security response headers `CFG-04..09`, OAuth client hygiene `OAU-01..09`).

---

## 2. Adapting the OWASP DSOVS Assessment Frontend (`assess.html`) to CASA 3.0

The [OWASP DevSecOps Verification Standard (DSOVS) Assessment UI](https://owasp.github.io/www-project-devsecops-verification-standard/assessment/assess.html) provides an exemplary client-side assessment workflow:
- Sticky navigation topbar with segmented `Assessment` / `Report` view switcher.
- Fixed left navigation rail with scroll-spy across domains/phases.
- Sticky progress bar tracking assessment completion.
- Per-control cards with expandable specification details, interactive `Verification evidence` checkboxes, `Notes` textarea, and `IndexedDB`-backed `Evidence screenshots` drag-and-drop that render as numbered figures (`Figure 1..N`) in the printable report.

### Key Architectural Adaptations for CASA 3.0
1. **Verdict Model instead of Maturity Levels (0–3):**
   - Whereas OWASP DSOVS rates controls on a 4-tier maturity scale (`Level 0 Initial` to `Level 3 Optimised`), CASA 3.0 uses strict compliance verdicts:
     - `PASS` (Compliant)
     - `FAIL` (Non-compliant — blocks certification)
     - `NOT_APPLICABLE` (Precondition absent on declared surfaces)
     - `Not_Covered` (Artifact or endpoint withheld/unreachable — blocks certification unless out of webhook scope)
2. **Dual-Mode Control Cards (Automated AL1 vs. Interactive AL2):**
   - **AL1 Controls (61 controls):** Populated automatically by the scanner engine (`POST /api/scan`) or by importing `.sarif`, `.cdx.json`, and `.har` files, displaying a terminal box with the automated tool signal and timestamp alongside optional assessor triage notes.
   - **AL2 Controls (15 controls):** Render the full DSOVS interactive assessment block: **Verification evidence** checklist (extracted from `CASA 3.0 (AL2) Test Guide.md`), **Notes** textarea, and **Evidence screenshots** uploader stored in `IndexedDB`.

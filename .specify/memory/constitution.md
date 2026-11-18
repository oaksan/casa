# ADA CASA 3.0 Web Assessment Framework Constitution

## Core Principles

### I. Specification-Driven Truth (CASA 3.0 Native)
Every control, domain, assurance level (`AL1`, `AL2`), pass/fail signal, and required evidence format MUST be derived directly from the official App Defense Alliance (ADA) `CASA 3.0 (AL1)` and `CASA 3.0 (AL2)` specifications and test guides (`CASA/CASA 3.0 *.md`).

### II. Deterministic Automation for AL1 (61 Controls)
All **61 AL1 requirements** across the 8 CASA 3.0 domains (`SCA`, `SAST`, `TLS`, `CFG`, `AUT`, `AZI`, `OAU`, `WHK`) MUST be evaluated deterministically without free-text questionnaires. Verdicts (`PASS`, `FAIL`, `NOT_APPLICABLE`, `Not_Covered`) are produced by automated scanner probes or ingested from open evidence formats (**OASIS SARIF 2.1.0**, **CycloneDX 1.5 / SPDX 2.3 SBOM**, **W3C HAR 1.2**).

### III. DSOVS-Inspired Interactive Workbench for AL2 (+15 Controls)
The **15 AL2 lab-adjudicated requirements** MUST provide a clean, self-contained browser assessment UX modeled after the [OWASP DevSecOps Verification Standard (`assess.html`)](https://owasp.github.io/www-project-devsecops-verification-standard/assessment/assess.html), featuring:
- Interactive **Verification evidence** checklists (`<ul class="evidence-list">`)
- Assessor **Notes** (`<textarea>`)
- **Evidence screenshots** drag-and-drop and upload persisted locally in `IndexedDB` and rendered as numbered figures (`Figure 1..N`) in the compliance report.

### IV. Open-Source First & Zero Proprietary Lock-in
The framework MUST NOT require commercial licenses (such as Burp Suite Professional) to execute AL1 assessments. Reference open-source tooling (`semgrep`, `gitleaks`, `syft`, `osv-scanner`, `trivy`, `testssl.sh`, `OWASP ZAP`, `nuclei`, `Playwright`, `mitmproxy`) and standard formats are first-class citizens.

### V. Local-First Privacy & Reproducibility
Assessment state (`localStorage`) and screenshot evidence (`IndexedDB`) persist locally in the assessor's browser, with deterministic one-click JSON export and print-ready PDF compliance reports.

## Licensing & Attribution Constraints
- **CASA Specifications**: Derived from [`appdefensealliance/ASA-WG`](https://github.com/appdefensealliance/ASA-WG) under **Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)**.
- **UI Inspiration**: Modeled on the OWASP DSOVS Self-Assessment tool structure, adapted to the four-state verdict model (`PASS`, `FAIL`, `NOT_APPLICABLE`, `Not_Covered`) and two-tier assurance architecture (`AL1` Automated vs. `AL2` Lab-Adjudicated) of CASA 3.0.

## Governance
All iterations follow the SpecKit Spec-Driven Development (SDD) lifecycle (`spec.md` → `plan.md` → `tasks.md` → implementation & validation).
At the end of every SDD iteration `NNN`:
1. All changes MUST be committed to `main` and tagged with `sdd-NNN` (`git tag sdd-NNN`).
2. Both the branch and the tag MUST be pushed to `https://github.com/oaksan/casa` (`git push origin main --tags`).

**Version**: 1.4.0 | **Ratified**: 2026-11-16 | **Last Amended**: 2026-11-18

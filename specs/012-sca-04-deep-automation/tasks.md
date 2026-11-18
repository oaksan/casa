# Tasks: SDD Iteration 12 — Control SCA-04 Deep Automation & Justification

**Input**: Design documents from `/specs/012-sca-04-deep-automation/`

## Phase 1: Scanner Engine Upgrade for SCA-04

- [x] T001 Implement `evaluate_sca04_sbom_completeness(repo, assessor_components, assessor_sbom_path)` in `casa-assessment/casa_audit/scanner.py`
- [x] T002 Validate CycloneDX 1.5+ / SPDX 2.3+ format & version, NTIA Minimum Elements on metadata and components, and Set Difference (`Assessor_SBOM - Published_SBOM`)
- [x] T003 Emit `CASA3-SCA-04` rule and findings in `casa-assessment/output/sca-findings.sarif`

## Phase 2: Academic Justification (`docs/justificativa.txt`)

- [x] T004 Append section `CONTROLE 04/61: SCA-04 (Iteração SDD 012)` to `/home/user/felipe/speckit/casa/docs/justificativa.txt` with CASA 3.0 normative basis and empirical OWASP Juice Shop findings (66 NTIA supplier gaps + 89 SetDiff components)

## Phase 3: Verification & Git Tagging (`sdd-012`)

- [x] T005 Add unit tests for `SCA-04` in `casa-assessment/tests/test_iteration1.py` and run test suite
- [x] T006 Commit changes to `main`, create Git tag `sdd-012`, and push branch and tags to `origin`

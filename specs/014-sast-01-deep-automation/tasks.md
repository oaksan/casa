# Tasks: SDD Iteration 14 — Control SAST-01 Deep Automation & Justification

**Input**: Design documents from `/specs/014-sast-01-deep-automation/`

## Phase 1: Scanner Engine & Semgrep Rule Upgrade for SAST-01

- [x] T001 Expand `CASA3-SAST-01-hardcoded-secret` in `casa-assessment/rules/casa3_al1_sast.yml`
- [x] T002 Implement `compute_shannon_entropy()` and `evaluate_sast01_secrets_and_entropy()` in `casa-assessment/casa_audit/scanner.py`
- [x] T003 Merge Semgrep AST and Shannon entropy findings into `casa-assessment/output/semgrep-sast.sarif`

## Phase 2: Academic Justification (`docs/justificativa.txt`)

- [x] T004 Append section `CONTROLE 06/61: SAST-01 (Iteração SDD 014)` to `/home/user/felipe/speckit/casa/docs/justificativa.txt` with CASA 3.0 normative basis and empirical OWASP Juice Shop findings (37 verified secret findings)

## Phase 3: Verification & Git Tagging (`sdd-014`)

- [x] T005 Update unit tests in `casa-assessment/tests/test_iteration1.py` and run test suite
- [x] T006 Commit changes to `main`, create Git tag `sdd-014`, and push branch and tags to `origin`

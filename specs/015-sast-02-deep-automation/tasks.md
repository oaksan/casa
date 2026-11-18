# Tasks: SDD Iteration 15 — Control SAST-02 Deep Automation & Justification

**Input**: Design documents from `/specs/015-sast-02-deep-automation/`

## Phase 1: Scanner Engine & Semgrep Rule Upgrade for SAST-02

- [x] T001 Expand `CASA3-SAST-02-committed-private-key` in `casa-assessment/rules/casa3_al1_sast.yml`
- [x] T002 Implement `evaluate_sast02_trust_material_and_keys()` in `casa-assessment/casa_audit/scanner.py`
- [x] T003 Merge Semgrep AST and keystore/PEM/BIP-39 findings into `casa-assessment/output/semgrep-sast.sarif`

## Phase 2: Academic Justification (`docs/justificativa.txt`)

- [x] T004 Append section `CONTROLE 07/61: SAST-02 (Iteração SDD 015)` to `/home/user/felipe/speckit/casa/docs/justificativa.txt` with CASA 3.0 normative basis and empirical OWASP Juice Shop findings (7 committed key/keystore/seed findings)

## Phase 3: Verification & Git Tagging (`sdd-015`)

- [x] T005 Update unit tests in `casa-assessment/tests/test_iteration1.py` and run test suite
- [x] T006 Commit changes to `main`, create Git tag `sdd-015`, and push branch and tags to `origin`

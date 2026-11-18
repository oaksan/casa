# Tasks: SDD Iteration 13 — Control SCA-05 Deep Automation & Justification

**Input**: Design documents from `/specs/013-sca-05-deep-automation/`

## Phase 1: Scanner Engine Upgrade for SCA-05

- [x] T001 Implement `compute_levenshtein_distance()`, `fetch_npm_maintainers()`, and `evaluate_sca05_malicious_and_typosquat()` in `casa-assessment/casa_audit/scanner.py`
- [x] T002 Emit `CASA3-SCA-05` rule and findings in `casa-assessment/output/sca-findings.sarif`

## Phase 2: Academic Justification (`docs/justificativa.txt`)

- [x] T003 Append section `CONTROLE 05/61: SCA-05 (Iteração SDD 013)` to `/home/user/felipe/speckit/casa/docs/justificativa.txt` with CASA 3.0 normative basis and empirical OWASP Juice Shop findings (`eslint-scope@3.7.2`, `ngy-cookie@6.0.0`, `epilogue-js@0.7`)

## Phase 3: Verification & Git Tagging (`sdd-013`)

- [x] T004 Update unit tests in `casa-assessment/tests/test_iteration1.py` and run test suite
- [x] T005 Commit changes to `main`, create Git tag `sdd-013`, and push branch and tags to `origin`

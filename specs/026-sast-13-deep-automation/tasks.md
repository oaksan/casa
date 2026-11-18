# Tasks: SDD Iteration 26 — Control SAST-13 Deep Automation & Justification

- [x] T001 Upgrade `SAST-13` rules (`mode: taint` + `get-password-query-logged` + Python) in `casa-assessment/rules/casa3_al1_sast.yml`
- [x] T002 Implement `evaluate_sast13_canary_log_replay()` in `casa-assessment/casa_audit/scanner.py`
- [x] T003 Validate `SAST-13` against OWASP Juice Shop (`routes/changePassword.ts:14` + canary password leak in `logs/access.log.*`)
- [x] T004 Append section `CONTROLE 18/61: SAST-13 (Iteração SDD 026)` to `docs/justificativa.txt`
- [x] T005 Update `casa-assessment/tests/test_iteration1.py`, run tests, commit, tag `sdd-026`, and push to GitHub

# Tasks: SDD Iteration 22 — Control SAST-09 Deep Automation & Justification

- [x] T001 Expand `CASA3-SAST-09-unsafe-deserialization` and add `CASA3-SAST-09-unsafe-deserialization-python` in `casa-assessment/rules/casa3_al1_sast.yml`
- [x] T002 Deduplicate Semgrep AST findings per `(sid, rel_p, line_no)` in `casa-assessment/casa_audit/scanner.py`
- [x] T003 Validate `SAST-09` against OWASP Juice Shop (8 unique findings including `routes/fileUpload.ts:80, 114` and `lib/xml.ts:35, 38`)
- [x] T004 Append section `CONTROLE 14/61: SAST-09 (Iteração SDD 022)` to `docs/justificativa.txt`
- [x] T005 Update `casa-assessment/tests/test_iteration1.py`, run tests, commit, tag `sdd-022`, and push to GitHub

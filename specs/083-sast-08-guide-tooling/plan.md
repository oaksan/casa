# Plan: SDD 083 — SAST-08 Guide Tooling (`semgrep` SQL/NoSQL Taint)

1. Convert `CASA3-SAST-08-*` in `casa-assessment/rules/casa3_al1_sast.yml` to `mode: taint` across `TS/JS`, `Python`, `Java`, and `Go` (excluding static `**/codefixes/**` snippet files and parameter-safe ORM/bind forms), and verify via `semgrep --validate` + Juice Shop pre-check.
2. Perform a single consolidated atomic update in `casa-assessment/casa_audit/scanner.py`: add `evaluate_sast08_sql_injection(repo)`, add `SAST-08` to `ERROR`-level filtering, and set `SAST-08` tool label.
3. Add `test_iteration83_sast08_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering multi-language taint `FAIL` (`TS`, `Python`, `Java`, `Go`) and parameterized queries `PASS`.
4. Execute full unittest suite to completion FIRST, then run live `POST /api/scan` against OWASP Juice Shop, document in `docs/justificativa2.txt`, commit, tag `sdd-083`, and push to `origin/main`.

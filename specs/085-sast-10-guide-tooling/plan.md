# Plan: SDD 085 — SAST-10 Guide Tooling (`semgrep` CWE-95 Taint)

1. Expand `CASA3-SAST-10-dynamic-code-execution*` (`TS/JS`, `Python`, `Java`, `Go`) in `casa-assessment/rules/casa3_al1_sast.yml` including reflective class/module loading (`Class.forName`, `importlib.import_module`, dynamic `require`) and validate via `semgrep --validate` + Juice Shop pre-check.
2. Perform a single consolidated atomic update in `casa-assessment/casa_audit/scanner.py`: add `evaluate_sast10_dynamic_execution(repo)`, add `SAST-10` to `ERROR`-level filtering, and set `SAST-10` tool label.
3. Add `test_iteration85_sast10_guide_tooling` in `casa-assessment/tests/test_iteration1.py` validating safe literal `eval`/`require`/`Class.forName` allowlisted `PASS` vs tainted `FAIL` across `TS`, `Python`, `Java` (reflection + `Runtime.exec`), and `Go` (`exec.Command`).
4. Run full unittest suite cleanly to completion, then run live `POST /api/scan` against OWASP Juice Shop, document in `docs/justificativa2.txt`, commit, tag `sdd-085`, and push to `origin/main`.

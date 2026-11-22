# Plan: SDD 086 — SAST-11 Guide Tooling (`semgrep` CWE-22 Taint)

1. Expand `CASA3-SAST-11-path-traversal*` (`TS/JS`, `Python`, `Java`, `Go`) in `casa-assessment/rules/casa3_al1_sast.yml` tracking HTTP params, uploaded filenames, and archive entry paths to file-system APIs with basename/secure_filename sanitizers, and validate via `semgrep --validate` + Juice Shop pre-check.
2. Perform a single consolidated atomic update in `casa-assessment/casa_audit/scanner.py`: add `evaluate_sast11_path_traversal(repo)`, add `SAST-11` to `ERROR`-level filtering, and set `SAST-11` tool label.
3. Add `test_iteration86_sast11_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering `PASS` (`path.basename`, `os.path.basename`, `secure_filename`, `filepath.Base`) and `FAIL` across `TS`, `Python` (Zip Slip), `Java`, and `Go`.
4. Run full unittest suite cleanly to completion, then run live `POST /api/scan` against OWASP Juice Shop, document in `docs/justificativa2.txt`, commit, tag `sdd-086`, and push to `origin/main`.

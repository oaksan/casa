# SDD 086: Guide-Compliant Reference Tooling for SAST-11 (`semgrep` Multi-Language Path Traversal & Zip Slip Taint Tracking)

## Control Reference
- **Control ID**: `SAST-11`
- **Guide Requirement**: File paths are not constructed from unvalidated user-supplied metadata (`Zero error-level findings of a file-system path built from user-supplied metadata without validation before use`).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`, `CodeQL`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-11-path-traversal*` Semgrep `mode: taint` rules in `casa-assessment/rules/casa3_al1_sast.yml` across `TS/JS` (adding `fs.writeFileSync`, `fs.promises.{readFile,writeFile}`, `res.download`), `Python` (`request.{args,form,json,files}`, `member.filename`, `zipinfo.filename`, `tarinfo.name` -> `open`, `send_file`, `shutil.copy`, `tar.extract`, `zf.extract`, sanitized by `os.path.basename`/`secure_filename`), `Java` (`getParameter`, `getOriginalFilename`, `ZipEntry.getName` -> `new File`/`Paths.get`/`Files.*`/`FileInputStream`/`FileOutputStream`, sanitized by `FilenameUtils.getName`), and `Go` (`URL.Query`, `CTX.Query/Param`, `fh.Filename`, `zf.Name` -> `os.Open`/`ReadFile`/`Create`/`WriteFile`, sanitized by `filepath.Base`), all at `severity: ERROR`.
2. Add `evaluate_sast11_path_traversal(repo)` in `casa-assessment/casa_audit/scanner.py` delegating cleanly to `_evaluate_semgrep_control_sarif(repo, "SAST-11")`, enforce `ERROR`-level gating for `SAST-11` in `run_sast_checks`, and expose `Semgrep AST 1.180.0 (Path Traversal & Zip Slip Taint Tracking + CWE-22 Ruleset, SARIF 2.1.0)`.
3. Validate rules via `semgrep --validate` + Juice Shop pre-check, add `test_iteration86_sast11_guide_tooling`, run full unittest suite cleanly BEFORE running live `POST /api/scan` against OWASP Juice Shop, record in `docs/justificativa2.txt`, commit, tag `sdd-086`, and push to GitHub.

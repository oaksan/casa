# SDD 085: Guide-Compliant Reference Tooling for SAST-10 (`semgrep` Dynamic Execution, Command & Reflection Taint Tracking)

## Control Reference
- **Control ID**: `SAST-10`
- **Guide Requirement**: No dynamic code execution on untrusted input (`eval`, `Function`, `exec`, reflection).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-10-dynamic-code-execution*` Semgrep `mode: taint` rules in `casa-assessment/rules/casa3_al1_sast.yml` across `TS/JS` (`eval`, `new Function`, `safeEval`, `vm.runInContext`/`runInNewContext`/`runInThisContext`, `exec`/`execSync`, dynamic `require`), `Python` (`eval`, `exec`, `compile`, `os.system`, `subprocess(..., shell=True)`, `importlib.import_module`, `__import__`), `Java` (`Class.forName` reflection, `Runtime.getRuntime().exec`, `ProcessBuilder`, `ScriptEngine.eval`), and `Go` (`exec.Command` shell/command execution), all at `severity: ERROR`.
2. Add `evaluate_sast10_dynamic_execution(repo)` in `casa-assessment/casa_audit/scanner.py` delegating to `_evaluate_semgrep_control_sarif(repo, "SAST-10")`, enforce `ERROR`-level gating for `SAST-10` in `run_sast_checks`, and expose `Semgrep AST 1.180.0 (Dynamic Code/Command/Reflection Taint Tracking + CWE-95 Ruleset, SARIF 2.1.0)`.
3. Validate rules via `semgrep --validate` + Juice Shop pre-check, add `test_iteration85_sast10_guide_tooling`, run full unittest suite cleanly BEFORE running live `POST /api/scan` against OWASP Juice Shop, record in `docs/justificativa2.txt`, commit, tag `sdd-085`, and push to GitHub.

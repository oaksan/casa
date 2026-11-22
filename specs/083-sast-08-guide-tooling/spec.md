# SDD 083: Guide-Compliant Reference Tooling for SAST-08 (`semgrep` Multi-Language SQL/NoSQL Taint Tracking)

## Control Reference
- **Control ID**: `SAST-08`
- **Guide Requirement**: Database access exclusively uses parameterized queries, ORMs, or escaped input (`Zero error-level findings of query construction by concatenation or interpolation on a tainted value`).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `CodeQL`, `semgrep`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Upgrade `CASA3-SAST-08-*` rules in `casa-assessment/rules/casa3_al1_sast.yml` to true **Semgrep `mode: taint` data-flow analysis** (`TS/JS`, `Python`, `Java`, `Go`) tracking untrusted HTTP/request inputs into unparameterized SQL (`sequelize.query`, `$DB.query`, `cursor.execute`, SQLAlchemy `text`, Java `Statement.execute*`/`createNativeQuery`, Go `db.Query`/`Exec`) and NoSQL (`$where`) sinks, excluding static educational snippet puzzles (`**/codefixes/**`) and ensuring parameterized queries (`?`, `%s`, `$1`, `replacements`, `PreparedStatement`) produce zero false positives.
2. Add `evaluate_sast08_sql_injection(repo)` in `casa-assessment/casa_audit/scanner.py` delegating to `_evaluate_semgrep_control_sarif(repo, "SAST-08")`, enforce strict `ERROR`-level gating in `run_sast_checks`, and expose `Semgrep AST 1.180.0 (SQL/NoSQL Taint Tracking + CWE-89/943 Ruleset, SARIF 2.1.0)` in `SAST-08` tool metadata.
3. Validate rules via `semgrep --validate`, add `test_iteration83_sast08_guide_tooling` (multi-language taint `FAIL` + parameterized `PASS`), run full unittest suite first, then test live against OWASP Juice Shop (`FAIL` confirming real SQL/NoSQL injection paths cleanly without `codefixes` snippet noise), record in `docs/justificativa2.txt`, commit, tag `sdd-083`, and push to GitHub.

# SDD 081: Guide-Compliant Reference Tooling for SAST-06 (`semgrep` Multi-Language CSPRNG Data-Flow Taint Tracking)

## Control Reference
- **Control ID**: `SAST-06`
- **Guide Requirement**: All security-relevant randomness uses a CSPRNG (zero `error`-level taint paths from non-CSPRNG or time-based seeds to token, key, nonce, salt, IV, or password-reset sinks).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-06-insecure-randomness*` Semgrep `mode: taint` rules in `casa-assessment/rules/casa3_al1_sast.yml` across `TS/JS` (`Math.random()`, `Date.now()`, `new Date()`, `crypto.pseudoRandomBytes`, `uuid.v1`), `Python` (`random.*`, `time.time()`, `uuid.uuid1`), `Java` (`Random().next*`, `Math.random()`, `System.currentTimeMillis()`), and `Go` (`math/rand`, `time.Now()`), tracking flows to `token`, `key`/`secret`, `nonce`, `salt`, `iv`, `otp`, and `password-reset` sinks at `severity: ERROR`.
2. Add `evaluate_sast06_csprng_randomness(repo)` delegating cleanly to `_evaluate_semgrep_control_sarif(repo, "SAST-06")`, enforce strict `ERROR`-level filtering for `SAST-06` in `run_sast_checks`, and report explicit CSPRNG taint-tracking tool metadata in `SAST-06`.
3. Validate rules via `semgrep --validate`, add `test_iteration81_sast06_guide_tooling` (multi-language `FAIL` + CSPRNG/benign `PASS`), test live against OWASP Juice Shop, record in `docs/justificativa2.txt`, commit, tag `sdd-081`, and push to GitHub.

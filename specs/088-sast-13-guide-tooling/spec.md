# SDD 088: Guide-Compliant Reference Tooling for SAST-13 (`semgrep` Sensitive Logging Taint + Scripted Canary Auth/Token/Payment Replay Harness)

## Control Reference
- **Control ID**: `SAST-13`
- **Guide Requirement**: Credentials, payment details, and tokens are never written to logs; session tokens appear only in irreversible hashed form (`ASVS V7.1.1`, `CWE-532`).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`, `scripted replay harness`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-13-sensitive-logging*` Semgrep `mode: taint` rules in `casa-assessment/rules/casa3_al1_sast.yml` across `TS/JS`, `Python` (adding `pattern-sanitizers` `hashlib.sha256`/`sha256`/`mask`/`redact`), `Java`, and `Go` tracking credentials, tokens, and card numbers to logging sinks with hash/mask sanitizers, all at `severity: ERROR`.
2. Upgrade `evaluate_sast13_canary_log_replay` in `casa-assessment/casa_audit/scanner.py` to replay **authentication**, **token-refresh**, and **payment** flows with unique canaries, search `logs/*.log*` and `log/*.log*` sinks, persist confirmed leaks to `output/semgrep-sast.sarif` (`CASA3-SAST-13-canary-log-leak`), and expose `evaluate_sast13_sensitive_logging(repo)` + explicit `Scripted Canary Replay Harness` status on both `PASS` and `FAIL`.
3. Validate rules via `semgrep --validate` + Juice Shop pre-check, add `test_iteration88_sast13_guide_tooling`, run full unittest suite cleanly BEFORE running live `POST /api/scan` against OWASP Juice Shop, record in `docs/justificativa2.txt`, commit, tag `sdd-088`, and push to GitHub.

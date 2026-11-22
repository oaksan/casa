# SDD 080: Guide-Compliant Reference Tooling for SAST-05 (`semgrep` AST + NIST SP 800-63B KDF Parameter & Per-Record CSPRNG Salt Provenance)

## Control Reference
- **Control ID**: `SAST-05`
- **Guide Requirement**: Passwords stored using an approved memory-hard KDF (`Argon2id`, `scrypt`, `bcrypt`, or `PBKDF2-HMAC-SHA256`) with NIST SP 800-63B parameter floors (`Argon2id` `m >= 19456` KiB and `t >= 2`, `scrypt` `N >= 32768`, `bcrypt` cost `>= 10`, `PBKDF2 >= 600000`) and a per-record CSPRNG salt.
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-05-*` Semgrep AST rules (`TS/JS` and `Python`) in `casa-assessment/rules/casa3_al1_sast.yml` with `metavariable-comparison` floor enforcement (`bcrypt` `< 10`, `PBKDF2` `< 600000` or weak digest / static salt, `scrypt` `N < 32768`, `Argon2` `memoryCost/memory_cost < 19456` or `timeCost/time_cost < 2`).
2. Enhance `evaluate_sast05_password_kdf` in `casa-assessment/casa_audit/scanner.py` to:
   - Combine Semgrep `SAST-05` AST findings with static KDF parameter resolution, Argon2 variant verification (`Argon2id`), PBKDF2 digest verification (`sha256`+), non-statically-determinable cost detection, and per-record CSPRNG salt provenance check (`crypto.randomBytes`, `os.urandom`, `secrets.token_*`, or library-internal CSPRNG salt).
   - Expose clear `Semgrep AST 1.180.0 + NIST SP 800-63B KDF & CSPRNG Salt Inspector` tool metadata in `run_sast_checks`.
3. Validate rules via `semgrep --validate`, add `test_iteration80_sast05_guide_tooling` covering compliant Argon2id/PBKDF2-HMAC-SHA256 (`PASS`) and sub-floor / wrong-algorithm / static-or-dynamic-unproven-salt sinks (`FAIL`), test live on OWASP Juice Shop (`FAIL`), record in `docs/justificativa2.txt`, commit, tag `sdd-080`, and push to GitHub.

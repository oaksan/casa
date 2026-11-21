# SDD 079: Guide-Compliant Reference Tooling for SAST-04 (`semgrep` Data-Flow Taint Tracking + Non-Security ETag/Cache Informational Separation)

## Control Reference
- **Control ID**: `SAST-04`
- **Guide Requirement**: No weak hash functions (`MD5`, `SHA-1`) used in any security-relevant context.
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`, `CodeQL`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Upgrade `CASA3-SAST-04-*` rules in `casa-assessment/rules/casa3_al1_sast.yml` from flat syntactic `createHash('md5')` checks to **Semgrep `mode: taint` data-flow analysis** (`JS/TS`, `Python`, `Java`, `Go`) tracking `MD5`/`SHA-1` sources into security-relevant sinks (passwords, tokens, signatures, HMACs, integrity/key derivation), with explicit `ETag`/`cacheKey` sanitizers.
2. Add `CASA3-SAST-04-weak-hash-informational` (`severity: INFO`) so non-security `ETag`/`cacheKey` uses emit informational SARIF notices (`level: "note"`) without causing false `FAIL` verdicts.
3. Enforce strict `error`-level filtering for `SAST-04` in `run_sast_checks` and add `evaluate_sast04_weak_hashes(repo)` in `casa-assessment/casa_audit/scanner.py`.
4. Verify multi-language taint detection (`FAIL`), ETag/cache-key `PASS` + informational notice, and live OWASP Juice Shop execution (`FAIL` with security sinks preserved), record in `docs/justificativa2.txt`, commit, tag `sdd-079`, and push to GitHub.

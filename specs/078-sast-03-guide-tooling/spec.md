# SDD 078: Guide-Compliant Reference Tooling for SAST-03 (`semgrep` Multi-Language AST + SARIF Error-Level Enforcement)

## Control Reference
- **Control ID**: `SAST-03`
- **Guide Requirement**: No deprecated or broken cipher algorithms (`DES`, `3DES`, `RC4`, `Blowfish`, or any cipher instantiated in `ECB` mode).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`, `CodeQL`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-03-*` Semgrep AST rules in `casa-assessment/rules/casa3_al1_sast.yml` across TypeScript/JavaScript (`CryptoJS.{DES,TripleDES,RC4,RC4Drop,Blowfish}.{encrypt,decrypt}`, `createCipheriv`/`createDecipheriv`, `node-forge` DES/3DES/AES-ECB/RC2), Python (`Crypto.Cipher`, `Cryptodome.Cipher`, `cryptography.hazmat` primitives/decrepit `TripleDES`/`Blowfish`/`ARC4`/`IDEA`/`ECB`), Java (`Cipher.getInstance` DES/DESede/RC4/Blowfish/`*/ECB/*`/implicit `"AES"`), Go (`crypto/des`, `crypto/rc4`, `blowfish`), and C# (`DES`, `TripleDES`, `RC2`, `CipherMode.ECB`), all at `severity: ERROR`.
2. Consolidate `run_sast_checks` in `casa-assessment/casa_audit/scanner.py` to execute a single `semgrep scan --json --sarif-output <semgrep-sast.sarif>` pass (instead of two sequential scans), enforce `error`-level filtering per the Test Guide's Verification criteria (`extra.severity == "ERROR"` / SARIF `level == "error"`), and expose `evaluate_sast03_banned_ciphers(repo)` using Semgrep directly.
3. Validate `casa3_al1_sast.yml` with `semgrep --validate`, run multi-language unit tests (`test_iteration78_sast03_guide_tooling`), test live against OWASP Juice Shop (`PASS` with zero false positives), record in `docs/justificativa2.txt`, commit, tag `sdd-078`, and push to GitHub.

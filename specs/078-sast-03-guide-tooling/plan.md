# Plan: SDD 078 — SAST-03 Guide Tooling (`semgrep`)

1. Expand `CASA3-SAST-03-*` rules in `casa-assessment/rules/casa3_al1_sast.yml` for JS/TS, Python (`PyCryptodome` + `cryptography`), Java JCA, Go `crypto/*`, and C# `.NET` cryptography APIs at `severity: ERROR`, and validate with `semgrep --validate`.
2. Optimize `run_sast_checks` in `casa-assessment/casa_audit/scanner.py` to produce both JSON and `semgrep-sast.sarif` (`SARIF 2.1.0`) in one `semgrep scan` pass, filter `SAST-03` strictly on `error`-level findings (`extra.severity == "ERROR"`), and add `evaluate_sast03_banned_ciphers(repo)`.
3. Add `test_iteration78_sast03_guide_tooling` in `casa-assessment/tests/test_iteration1.py` validating JS/TS, Python, Java, Go, and C# detections plus compliant AES-GCM `PASS`.
4. Verify live on OWASP Juice Shop (`POST /api/scan`), record SDD 078 in `docs/justificativa2.txt`, commit, tag `sdd-078`, and push to `origin/main`.

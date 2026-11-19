# Plan — SDD 070: Omit Non-blocking Findings Across All Controls

1. Remove `non_blocking_sca01_info`, `sca03_non_blocking`, and `cert_audit['warnings']` tail formatting from `SCA-01`, `SCA-03`, and `TLS-04` logs in `casa-assessment/casa_audit/scanner.py` without altering triage logic or SARIF `error` emission.
2. Verify empirically against live OWASP Juice Shop (`http://localhost:3000`) that 0/61 control logs contain `non-blocking` or `informational`.
3. Add global assertions in `casa-assessment/tests/test_iteration1.py`, document SDD 070 in `docs/justificativa.txt`, run `unittest`, and commit/tag `sdd-070`.

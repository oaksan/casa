# Tasks — SDD 070: Omit Non-blocking Findings Across All Controls

- [x] Audit all 61 control formatters in `casa-assessment/casa_audit/scanner.py` for non-blocking / informational sections
- [x] Omit `Non-blocking` / `Informational` blocks from `SCA-01`, `SCA-03`, and `TLS-04` logs while preserving full triage filtering
- [x] Validate against live OWASP Juice Shop (`ANY_NON_BLOCKING_IN_61_LOGS: []`)
- [x] Add global regression assertions in `casa-assessment/tests/test_iteration1.py` & document in `docs/justificativa.txt`
- [x] Run full `unittest` suite
- [x] Commit, tag `sdd-070`, and push `origin main --tags`

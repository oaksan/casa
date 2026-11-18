# Plan — SDD 060: OAU-03 Deep Automation

1. Extend `http_probe` in `casa-assessment/casa_audit/scanner.py` with optional `max_bytes: int = 16384` so full JSON runtime configuration payloads (`/rest/admin/application-configuration`) are read completely while keeping bounded defaults.
2. Replace `open_redir_vuln` aliasing in `OAU-03` with dedicated registered-URI inspection (live config + HAR + bundles + YAML) and active callback/forwarding fuzzing (`redirect`, `next`, `continue`, `return_to`, `RelayState`, `to`).
3. Detect `3xx Location`, meta-refresh, and script redirects resolving outside observed OAuth redirect hosts, and emit `CASA3-OAU-03` SARIF results.
4. Validate against live OWASP Juice Shop (`http://localhost:3000`), document in `docs/justificativa.txt`, assert in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-060`.

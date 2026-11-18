# Plan — SDD 063: OAU-06 Deep Automation

1. Add `evaluate_oau06_client_secret_scanner` in `casa-assessment/casa_audit/scanner.py` to scan binaries, sources, JS bundles, and HAR token traffic, and test extracted secrets against loopback token endpoints.
2. Replace the fake `OAU-06` stub in `run_dynamic_and_protocol_checks` with real `evaluate_oau06_client_secret_scanner` invocation and `CASA3-OAU-06` SARIF emission, plus static execution in `run_automated_al1_scan` when `Mobile`/`Native` surfaces are selected without `target_url`.
3. Validate empirically against Juice Shop and mock `.apk` + `/oauth/token` server vs PKCE Kotlin fixtures.
4. Document Control 55/61 in `docs/justificativa.txt`, add unit assertions in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-063`.

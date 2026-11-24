# Implementation Plan 118 — AZI-05 (`OWASP ZAP 6/7` + `LFI/Traversal & RFI Matrix`)

1. Extract `evaluate_azi05_lfi_rfi(...)` in `casa-assessment/casa_audit/scanner.py` combining:
   - Focused OWASP ZAP active LFI/RFI scan (`active_scan_rules=[6, 7]`) exporting `output/zap-lfi-report.json` + `output/zap-lfi-findings.sarif`;
   - Authenticated path-traversal payload matrix (`encoded`, `double-encoded`, `null-byte`, `absolute`, `UNC`) across `/ftp/`, `/support/logs/`, discovered parameterized endpoints, and optional `param_targets`;
   - Ephemeral HTTP RFI callback server (`_RfiCallbackHandler` on `127.0.0.1:0`) testing `POST /profile/image/url` (when authenticated) and path/URL query parameters, confirming both out-of-band server HTTP fetches and reflected remote inclusion markers (`CASA3_RFI`);
   - Shared redacted HAR 1.2 capture (`output/azi05-replayed.har`), structured JSON (`output/azi05-lfi-rfi-audit.json`), and `CASA3-AZI-05` SARIF 2.1.0 entries.
2. Wire `results["AZI-05"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration118_azi05_guide_tooling` in `casa-assessment/tests/test_iteration1.py` verifying PASS on strict path canonicalization / URL allowlisting and FAIL confirmed simultaneously by real OWASP ZAP (`6`/`7`), path traversal file leak, and RFI callback + inclusion marker, with `[REDACTED]` HAR validation.
4. Append `CONTROLE 48/61: AZI-05 (Iteração SDD 118)` to `docs/justificativa2.txt`.
5. Run full `unittest` suite (`51` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`), check off `tasks.md`, commit, tag `sdd-118`, and push `main` + tags.

# Implementation Plan 119 — AZI-06 (`OWASP ZAP 20019/20014` + `Open Redirect & HPP Harness`)

1. Add `follow_redirects: bool = True` support to `_make_redacted_har_probe(...)` in `casa-assessment/casa_audit/scanner.py` (with `_NoRedirectHandler`).
2. Extract `evaluate_azi06_open_redirect_hpp(...)` in `casa-assessment/casa_audit/scanner.py` combining:
   - Focused OWASP ZAP active scan (`active_scan_rules=[20019, 20014]`) seeded cleanly on redirect/auth endpoints (`output/zap-redirect-report.json` + `output/zap-redirect-findings.sarif`);
   - `NoRedirect` inspection of 3xx `Location`, HTML `<meta http-equiv="refresh">`, and inline `<script>window.location...` targets across direct, protocol-relative (`//`), query-substring (`?allowed`), userinfo (`@`), discovered redirect-like crawl parameters (`next`, `redirect`, `return`, `url`, `to`, `callback`, `dest`), and custom `redirect_targets`;
   - HTTP Parameter Pollution (HPP) duplicated-parameter authorization differential probes (`?to=...&to=...`, `/rest/basket/{id}?id=...`, and configurable `hpp_targets`) checking both status flips and off-allowlist redirect flips (`CWE-235`);
   - Redacted HAR 1.2 (`output/azi06-replayed.har`), structured JSON (`output/azi06-redirect-hpp-audit.json`), and `CASA3-AZI-06` SARIF 2.1.0 entries.
3. Wire `results["AZI-06"]` inside `run_dynamic_and_protocol_checks`.
4. Add `test_iteration119_azi06_guide_tooling` in `casa-assessment/tests/test_iteration1.py` verifying PASS on strict hostname allowlist + HPP rejection and FAIL confirmed simultaneously by real OWASP ZAP `20019`, off-allowlist 302/JS redirect bypass, and HPP authorization outcome flip, with `[REDACTED]` HAR validation.
5. Append `CONTROLE 49/61: AZI-06 (Iteração SDD 119)` to `docs/justificativa2.txt`.
6. Run full `unittest` suite (`52` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`), check off `tasks.md`, commit, tag `sdd-119`, and push `main` + tags.

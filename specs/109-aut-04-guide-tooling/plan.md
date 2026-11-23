# Implementation Plan 109 — AUT-04 (`OWASP ZAP 3/10024/10025` + `HAR URL/Referer Inspector`)

1. Enable ZAP passive rules `3`, `10024`, and `10025` at `Low` threshold in `run_zap_automation`, and record `request_headers` alongside `headers` on every `crawled_exchanges` entry captured by `http_probe` so outbound request `Referer` headers are faithfully audited.
2. Extract `evaluate_aut04_url_token_leak(...)` in `casa-assessment/casa_audit/scanner.py` combining OWASP ZAP (`3`/`10024`/`10025`), crawl/HAR inspection across URLs, query strings, fragments, outbound request `Referer` and redirect `Location` headers, active CWE-598 GET credential probe, repo OAuth `#access_token=` audit, SARIF 2.1.0 (`CASA3-AUT-04`) generation, and dedicated redacted HAR 1.2 persistence (`output/aut04-replayed.har`).
3. Wire `results["AUT-04"]` inside `run_dynamic_and_protocol_checks`, passing `zap_report=zap_domain4_report` so full scans incur zero redundant ZAP launches.
4. Add `test_iteration109_aut04_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering:
   - Clean authenticated crawl + POST-only change-password (`PASS`, real OWASP ZAP execution + redacted HAR verified);
   - Session/JWT token leak detected in URL / outbound `Referer` via ZAP `10024` / crawl `request_headers` (`FAIL`);
   - CWE-598 GET query credential endpoint acceptance (`FAIL` + password redaction `[REDACTED]` in HAR).
5. Append `CONTROLE 39/61: AUT-04 (Iteração SDD 109)` to `docs/justificativa2.txt`.
6. Run full `unittest` suite (`42` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`), check off `tasks.md`, commit, tag `sdd-109`, and push `main` + tags.

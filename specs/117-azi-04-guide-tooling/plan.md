# Implementation Plan 117 — AZI-04 (`OWASP ZAP 90020` + `OOB HTTP/DNS Callback Harness`)

1. Extract `evaluate_azi04_cmd_injection(...)` in `casa-assessment/casa_audit/scanner.py` combining:
   - Focused OWASP ZAP active Remote OS Command Injection scan (`active_scan_rules=[90020]`) exporting `output/zap-cmdi-report.json` + `output/zap-cmdi-findings.sarif`;
   - Ephemeral OOB HTTP callback server (`127.0.0.1:0`) and UDP DNS QNAME callback listener (`127.0.0.1:0`) with clean packet parsing and fast NXDOMAIN responses;
   - Authenticated multi-parameter payloads covering HTTP OOB (`curl`), DNS OOB (`nslookup`/`dig`), backticks, pipes, and subshells across query, path, JSON body, form, and discovered crawl query endpoints;
   - Shared redacted HAR 1.2 recording (`output/azi04-replayed.har`), structured JSON (`output/azi04-cmdi-audit.json`), and `CASA3-AZI-04` SARIF 2.1.0 entries.
2. Wire `results["AZI-04"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration117_azi04_guide_tooling` in `casa-assessment/tests/test_iteration1.py` verifying PASS on hardened parameters and FAIL confirmed simultaneously by real OWASP ZAP `90020`, direct `uid=` output marker, live OOB HTTP callback, and live OOB DNS QNAME callback with `[REDACTED]` HAR validation.
4. Append `CONTROLE 47/61: AZI-04 (Iteração SDD 117)` to `docs/justificativa2.txt`.
5. Run full `unittest` suite (`50` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`), check off `tasks.md`, commit, tag `sdd-117`, and push `main` + tags.

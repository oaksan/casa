# Implementation Plan 116 — AZI-03 (`sqlmap` + `OWASP ZAP SQLi` + `NoSQL Differential/Operator`)

1. Add `SQLMAP_BIN` constant to `casa-assessment/casa_audit/scanner.py`.
2. Add `run_sqlmap_scan(...)` in `casa-assessment/casa_audit/scanner.py` invoking `/home/user/.local/bin/sqlmap` in an isolated temporary output directory (`--batch --flush-session --level=1 --risk=1 --technique=BEU --disable-coloring`), parsing structured injection blocks from `sqlmap`'s `log` output and emitting redacted `output/azi03-sqlmap-report.json`.
3. Extract shared `_make_redacted_har_probe(...)` helper and `evaluate_azi03_sqli_nosql(...)` combining:
   - Authenticated `run_sqlmap_scan(...)` across discovered/target query and POST JSON endpoints;
   - Focused OWASP ZAP active SQLi scan (`active_scan_rules=[40018, 40024]`) exporting `output/zap-sqli-report.json` + `output/zap-sqli-findings.sarif`;
   - Authenticated SQLi auth-bypass (`' OR 1=1--`), differential boolean (`')) OR 1=1--`), and SQLite error-based (`'))`) probes (`CWE-89`);
   - Non-destructive NoSQL `$where` differential probe (`' || true || '`) + JSON operator injection probes (`$ne`, `$regex`, `$gt`) checking both auth bypass and result-set alteration (`CWE-943`);
   - Evidence artifacts `output/azi03-sqli-nosql-audit.json`, redacted `output/azi03-replayed.har`, and `CASA3-AZI-03` SARIF 2.1.0 entries.
4. Wire `results["AZI-03"]` inside `run_dynamic_and_protocol_checks`.
5. Add `test_iteration116_azi03_guide_tooling` in `casa-assessment/tests/test_iteration1.py` exercising real `sqlmap` + real OWASP ZAP (`40018`/`40024`) + NoSQL `$where`/operator probes on both PASS (parameterized SQLite & rejected NoSQL operators) and FAIL (real SQLite SQLi & NoSQL result-set alteration), plus HAR redaction.
6. Append `CONTROLE 46/61: AZI-03 (Iteração SDD 116)` to `docs/justificativa2.txt`.
7. Run full `unittest` suite (`49` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`) with refreshed `casa_audit` daemon, check off `tasks.md`, commit, tag `sdd-116`, and push `main` + tags.

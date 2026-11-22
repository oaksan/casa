# Plan: SDD 088 — SAST-13 Guide Tooling (`semgrep` + Scripted Canary Replay Harness)

1. Expand `CASA3-SAST-13-sensitive-logging*` in `casa-assessment/rules/casa3_al1_sast.yml` for `TS/JS`, `Python` (fixing missing `pattern-sanitizers`), `Java`, and `Go`, validating via `semgrep --validate`.
2. Perform a single consolidated atomic update in `casa-assessment/casa_audit/scanner.py`: add `evaluate_sast13_sensitive_logging(repo)`, add `SAST-13` to `ERROR`-level gating + explicit `tool_label` in `run_sast_checks`, upgrade `evaluate_sast13_canary_log_replay` to replay auth + token-refresh + payment canaries and emit SARIF 2.1.0 entries on leak, and always append canary verification results in `run_automated_al1_scan`.
3. Add `test_iteration88_sast13_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering multi-language taint `FAIL`, hashed/masked `PASS`, and scripted auth/token-refresh/payment canary replay (`FAIL` with SARIF output vs clean log `PASS`).
4. Run full unittest suite cleanly to completion, then run live `POST /api/scan` against OWASP Juice Shop, document in `docs/justificativa2.txt`, commit, tag `sdd-088`, and push to `origin/main`.

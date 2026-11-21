# Plan: SDD 079 — SAST-04 Guide Tooling (`semgrep` `mode: taint`)

1. Replace flat `SAST-04` syntactic rules in `casa-assessment/rules/casa3_al1_sast.yml` with `mode: taint` data-flow rules (`JS/TS`, `Python`, `Java`, `Go`), cross-file `security.hash`/HMAC sink rules (`ERROR`), and non-security `ETag`/`cacheKey` informational rules (`INFO`), validating via `semgrep --validate`.
2. Generalize the helper logic in `casa-assessment/casa_audit/scanner.py` so `SAST-03` and `SAST-04` share one `error`-level Semgrep SARIF evaluator (`_evaluate_semgrep_control_sarif(repo, control_id, ...)` + `evaluate_sast03_banned_ciphers` + `evaluate_sast04_weak_hashes`) without duplicating SARIF parsing!
3. Enforce `extra.severity == "ERROR"` for `SAST-04` inside `run_sast_checks` and report any informational (`INFO`) ETag/cache-key count when `SAST-04` passes.
4. Add `test_iteration79_sast04_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering taint `FAIL` across JS/TS/Python/Java/Go and `ETag`/`cache_key` `PASS` (with informational count > 0).
5. Run unittest suite, run live `POST /api/scan` against OWASP Juice Shop, document in `docs/justificativa2.txt`, commit, tag `sdd-079`, and push to `origin/main`.

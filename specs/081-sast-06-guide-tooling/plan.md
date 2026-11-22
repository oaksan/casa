# Plan: SDD 081 — SAST-06 Guide Tooling (`semgrep` CSPRNG Taint)

1. Expand `CASA3-SAST-06-insecure-randomness` (`TS/JS`) and `CASA3-SAST-06-insecure-randomness-python` (`Python`), plus add `CASA3-SAST-06-insecure-randomness-java` and `CASA3-SAST-06-insecure-randomness-go` in `casa-assessment/rules/casa3_al1_sast.yml`, validating with `semgrep --validate`.
2. Add `evaluate_sast06_csprng_randomness(repo)` using `_evaluate_semgrep_control_sarif(repo, "SAST-06")`, add `SAST-06` to `ERROR`-level severity filtering in `run_sast_checks`, and set explicit `SAST-06` tool label in `casa-assessment/casa_audit/scanner.py`.
3. Add `test_iteration81_sast06_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering benign/CSPRNG `PASS` (`crypto.randomBytes`, `secrets.token_urlsafe`, benign price randomization) and multi-language `FAIL` (TS `resetToken`/`nonce`, Python `time.time()`/`salt`, Java `Random`/`IvParameterSpec`, Go `math/rand`/`token`).
4. Run full unittest suite, run live `POST /api/scan` against OWASP Juice Shop, document in `docs/justificativa2.txt`, commit, tag `sdd-081`, and push to `origin/main`.

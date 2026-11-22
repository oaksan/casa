# Tasks 094 — TLS-06 Guide-Compliant Tooling

- [x] Benchmark individual and combined `testssl.sh` vulnerability flags (`-H -I -T -C` completes in ~13.5s vs blocking `-R`/`-BB`).
- [x] Update `evaluate_tls06_vulnerabilities` in `casa-assessment/casa_audit/scanner.py` to use `("-H", "-I", "-T", "-C")` (`timeout_sec=30`) + deterministic `secure_renego` / `ROBOT` completion.
- [x] Run targeted `test_iteration94_tls06_guide_tooling` first (<25s), then full `unittest` suite (`27` tests `OK`).
- [x] Start Juice Shop (`3000`) & `casa_audit` (`8080`) daemons and verify live `POST /api/scan` (`STATUS: ok | COUNT: 61`, `TLS-01..TLS-06`).
- [ ] Commit SDD 094 files, create annotated tag `sdd-094`, and push `main` + tags to `origin`.

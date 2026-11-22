# Plan: SDD 082 — SAST-07 Guide Tooling (`semgrep` + `ZAP` / Lab-Account Probe)

1. Expand `CASA3-SAST-07-mass-assignment*` AST rules (`TS/JS`, `Python`, `Java`, `Go`) in `casa-assessment/rules/casa3_al1_sast.yml` and validate with `semgrep --validate`.
2. Upgrade `casa-assessment/casa_audit/scanner.py` in a single atomic batch: add `evaluate_sast07_framework_binding(repo)`, upgrade `evaluate_sast07_mass_assignment_probe` for full lab-account login + `PUT`/`PATCH` update + `GET` read-back + `OWASP ZAP` SARIF correlation + active SARIF 2.1.0 persistence, and update `SAST-07` tool labeling (`Semgrep AST 1.180.0 + OWASP ZAP + Lab-Account Update/Read-Back Probe`).
3. Add `test_iteration82_sast07_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering multi-language unrestricted-binder detection, local mock HTTP update + read-back verification (`FAIL` vs `PASS`), and `docs/justificativa2.txt` registration.
4. Run full unittest suite, run live `POST /api/scan` against OWASP Juice Shop, commit, tag `sdd-082`, and push to `origin/main`.

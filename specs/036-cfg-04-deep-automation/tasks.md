# Tasks — Iteration 036 (`CFG-04`)

- [x] Implement multi-route HTML CSP evaluator (`script-src` / `default-src` precedence + `unsafe-inline`, `unsafe-eval`, `*`, `data:`) in `casa-assessment/casa_audit/scanner.py`.
- [x] Validate against OWASP Juice Shop (`http://localhost:3000`) — 39/39 HTML routes flagged in `output/dast-findings.sarif`.
- [x] Document theoretical rationale and empirical results in `docs/justificativa.txt` (`CONTROLE 28/61: CFG-04`).
- [x] Add regression check to `casa-assessment/tests/test_iteration1.py` and run `unittest`.
- [x] Commit, tag `sdd-036`, and push `main` + `--tags` to `origin`.

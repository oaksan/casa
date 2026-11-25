# Plan 131 — WHK-03 Guide-Compliant Tooling

1. Add `CASA3-WHK-03-hardcoded-signing-secret` to `casa-assessment/rules/casa3_al1_oauth.yml`.
2. Add `evaluate_whk03_ssrf_protection` right after `evaluate_whk03_ssrf_and_signing_secrets` in `casa-assessment/casa_audit/scanner.py` integrating `_make_redacted_har_probe`, `_run_gitleaks_sarif` (`dir` + `git`), and `_run_oauth_semgrep_sarif`, preserving the 4-tuple return of `evaluate_whk03_ssrf_and_signing_secrets`.
3. Wire `evaluate_whk03_ssrf_protection` in `run_dynamic_and_protocol_checks` (`results["WHK-03"]`).
4. Add `test_iteration131_whk03_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering PASS (HTTP 400 rejecting all 11 CIDR/redirect/rebind vectors + 0 OOB hits + `process.env.WEBHOOK_SECRET` + 0 gitleaks/Semgrep hits + redacted HAR), FAIL (SSRF callback OOB direct/302 fetches + `whsec_` signing secret caught by gitleaks dir/git & Semgrep & HAR), and `Not_Covered` (no webhook facilities).
5. Document `CONTROLE 61/61: WHK-03 (Iteração SDD 131)` + final 61/61 completion note in `docs/justificativa2.txt`, run isolated + full `unittest` suite (`64` tests), execute final live OWASP Juice Shop scan verifying all `61/61` controls, commit, tag `sdd-131`, and push.

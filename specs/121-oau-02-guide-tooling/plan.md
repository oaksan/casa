# Implementation Plan 121 — OAU-02 (`Intercepting Proxy PKCE` + `Semgrep OAU-02`)

1. Add `CASA3-OAU-02-weak-or-plain-pkce` to `casa-assessment/rules/casa3_al1_oauth.yml` (validating with `semgrep --validate`) to flag `code_challenge_method=plain` and client OAuth authorize URL templates missing `code_challenge` / `S256`.
2. Refactor proxy interception from `evaluate_oau01_grant_type` into shared helper `_run_oauth_intercepting_proxy(...)` supporting `OAuth` authorization & token param capture (`response_type`, `grant_type`, `code_challenge`, `code_challenge_method`, `code_verifier`, `redirect_uri`, `state`, `nonce`) and redacted HAR 1.2 export (masking `code_verifier`, `code`, `client_secret`, `password`, `Authorization`, `Cookie`, `Set-Cookie`).
3. Scope `Semgrep` filtering in `evaluate_oau01_grant_type` (`"OAU-01" in rule_id`) and implement `evaluate_oau02_pkce(...)` combining:
   - Proxied PKCE capture + RFC 7636 §4.2 `S256` cryptographic proof check (`urlsafe_b64encode(sha256(verifier)) == challenge`) + optional negative replay without/mismatched `code_verifier`;
   - Real **Semgrep** scan (`"OAU-02" in rule_id`, exporting `output/oau02-semgrep.sarif`);
   - Hybrid served JS bundle & client source inspection;
   - Evidence artifacts `output/oau02-pkce-audit.json`, redacted `output/oau02-replayed.har`, and `CASA3-OAU-02` SARIF 2.1.0 entries.
4. Wire `results["OAU-02"]` inside `run_dynamic_and_protocol_checks`.
5. Add `test_iteration121_oau02_guide_tooling` in `casa-assessment/tests/test_iteration1.py` exercising valid `S256` proxied PKCE + Semgrep (`PASS`), and `plain`/mismatched verifier/absent PKCE + Semgrep hit (`FAIL`), with `[REDACTED]` HAR verified.
6. Append `CONTROLE 51/61: OAU-02 (Iteração SDD 121)` to `docs/justificativa2.txt`.
7. Run full `unittest` suite (`54` tests) to completion, verify live OWASP Juice Shop (`POST /api/scan`), check off `tasks.md`, commit, tag `sdd-121`, and push `main` + tags.

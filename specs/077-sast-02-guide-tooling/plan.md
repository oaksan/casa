# Plan: SDD 077 — SAST-02 Guide Tooling (`gitleaks`)

1. Extract shared Gitleaks helpers `_write_gitleaks_triage_config` and `_run_gitleaks_sarif(mode, repo, sarif_out)` in `casa-assessment/casa_audit/scanner.py` so `run_gitleaks_for_sast` (`dir`) and new `run_gitleaks_git_history` (`git`) share one TOML config builder and SARIF 2.1.0 parser.
2. Refactor `evaluate_sast02_trust_material_and_keys` to accept optional `gitleaks_dir_hits` and `gitleaks_git_hits`, run `gitleaks git` over `.git` history (replacing `git log -S`), integrate Gitleaks private-key hits (`dir` + `git`), inspect certificate/keystore extensions + shipped archives, and preserve PEM/BIP-39 scanning.
3. Wire `gitleaks_hits` (`dir`) and `run_gitleaks_git_history(repo)` into `run_sast_checks`, updating `SAST-02`'s `tool` label and `SARIF` evidence references.
4. Add unit test `test_iteration77_sast02_guide_tooling` covering shipped keystore/PEM detection, synthetic `.git` commit history detection via `gitleaks git`, and OWASP Juice Shop / `docs/justificativa2.txt` validation.
5. Verify against OWASP Juice Shop (`POST /api/scan`), record iteration details in `docs/justificativa2.txt`, commit, tag `sdd-077`, and push to `origin/main`.

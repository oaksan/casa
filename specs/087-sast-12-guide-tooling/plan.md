# Plan: SDD 087 — SAST-12 Guide Tooling (`semgrep` + `trivy` + `docker`)

1. Expand `CASA3-SAST-12-hardcoded-config-secrets` (adding Python/Terraform secrets) and add `CASA3-SAST-12-dockerfile-env-secret` in `casa-assessment/rules/casa3_al1_sast.yml`; validate via `semgrep --validate`.
2. Perform a single consolidated atomic update in `casa-assessment/casa_audit/scanner.py`: add `run_trivy_sast12(repo)` writing native `output/trivy-sast12.sarif` (`SARIF 2.1.0`), upgrade `evaluate_sast12_secrets_management_and_iac` to fuse Secrets Manager SDK inventory + IaC/config scan + Trivy secret/misconfig + Docker image env/layer check, and update `SAST-12` tool label + `Trivy SARIF Evidence` reference in `run_sast_checks`.
3. Add `test_iteration87_sast12_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering Trivy secret/Dockerfile detection (`FAIL`), Secrets Manager SDK inventory detection, and compliant Vault/SecretsManager repo (`PASS`).
4. Run full unittest suite cleanly to completion, then run live `POST /api/scan` against OWASP Juice Shop, record in `docs/justificativa2.txt`, commit, tag `sdd-087`, and push to `origin/main`.

# SDD 087: Guide-Compliant Reference Tooling for SAST-12 (`semgrep` + `trivy` + `docker` Secrets Store & Image Layer Inspector)

## Control Reference
- **Control ID**: `SAST-12`
- **Guide Requirement**: Server-side secrets are held in a managed secrets store, not in config files or environment baked into images (`ASVS V6.4.1`, `CWE-522`).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`, `trivy`, `docker`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-12-*` Semgrep rules in `casa-assessment/rules/casa3_al1_sast.yml` (`TS/JS`, `Python`, `Terraform`, `Dockerfile ENV`) and validate with `semgrep --validate`.
2. Implement `run_trivy_sast12(repo)` executing official `trivy fs --scanners secret,misconfig --format sarif` (`output/trivy-sast12.sarif`) with test/log/vendor exclusions and integrate it with `evaluate_sast12_secrets_management_and_iac(repo)` in `casa-assessment/casa_audit/scanner.py`.
3. Generalize Docker container `.Config.Env` and baked-file inspection for local images declared in `Dockerfile` / `docker-compose*.yml` (including `bkimminich/juice-shop:latest`), inventory Secrets Manager SDK call sites across manifests (`package.json`, `requirements*.txt`, `pom.xml`, `go.mod`) and source trees, and update `SAST-12` tool metadata to cite `Semgrep AST 1.180.0 + Trivy v0.76.2 + Docker`.
4. Add `test_iteration87_sast12_guide_tooling`, run full unittest suite cleanly BEFORE live `POST /api/scan` against OWASP Juice Shop, document in `docs/justificativa2.txt`, commit, tag `sdd-087`, and push to GitHub.

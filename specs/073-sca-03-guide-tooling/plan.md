# Implementation Plan: Iteration 73 — Guide-Compliant Reference Tooling for SCA-03

**Branch**: `[073-sca-03-guide-tooling]` | **Date**: 2026-11-21 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/073-sca-03-guide-tooling/spec.md)

## Summary

1. Install official open-source `trivy` binary (`v0.76.2`) in `/home/user/.local/bin/trivy`.
2. Update `evaluate_sca03_container_os` in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py):
   - Resolve `TRIVY_BIN = shutil.which("trivy") or "/home/user/.local/bin/trivy"`.
   - Execute `trivy image --pkg-types os --list-all-pkgs --format json` (using `--skip-db-update` fallback when cached DB exists to remain fast and deterministic) against declared container images / `Dockerfile` base stages (with `DOCKER_API_VERSION=1.44`), plus emit native SARIF 2.1.0 (`output/trivy-sca03.sarif`).
   - Filter OS vulnerabilities by `Severity in {"HIGH", "CRITICAL"}` and distribution status (`will_not_fix` / `end_of_life` excluded only where mitigated/marked by distro), include vulnerabilities with no published fix (`Status == "affected"`), check `Dockerfile` `@sha256:` digest pinning, and enrich `sbom.cdx.json` with the extracted OS packages (`Packages` from Trivy JSON / `dpkg`).
   - Keep `Not_Covered` clean when no `Dockerfile` exists (`casa` repo) and retain structured fallback only if neither `trivy` nor container daemon is reachable.
3. Add `test_iteration73_sca03_guide_tooling` in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py).
4. Record `CONTROLE 03/61: SCA-03 (Iteração SDD 073)` in [`docs/justificativa2.txt`](file:///home/user/felipe/speckit/casa/docs/justificativa2.txt).
5. Run `unittest` and live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000` + `/home/user/felipe/speckit/juice-shop-master`).

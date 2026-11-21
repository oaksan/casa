# Implementation Plan: Iteration 74 — Guide-Compliant Reference Tooling for SCA-04

**Branch**: `[074-sca-04-guide-tooling]` | **Date**: 2026-11-21 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/074-sca-04-guide-tooling/spec.md)

## Summary

1. Install official open-source `cyclonedx-cli` (`v0.33.1`) binary at `/home/user/.local/bin/cyclonedx` alongside `syft` (`v1.57.2`).
2. Enhance `evaluate_sca04_sbom_completeness` in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py):
   - Add `CYCLONEDX_BIN` resolution and helper `run_cyclonedx_validate_and_diff(...)`.
   - Validate published CycloneDX SBOMs (`>= 1.5`) and assessor `sbom.cdx.json` formally with `cyclonedx validate --input-format json --input-version v1_<minor> --fail-on-errors`.
   - Execute `cyclonedx diff <published> <assessor> --from-format json --to-format json --component-versions --output-format json` writing `output/cyclonedx-diff.json`.
   - Maintain full NTIA Minimum Elements checks and normalized Set Difference `(Assessor_SBOM − Published_SBOM)`.
3. Add `test_iteration74_sca04_guide_tooling` in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py).
4. Record `CONTROLE 04/61: SCA-04 (Iteração SDD 074)` in [`docs/justificativa2.txt`](file:///home/user/felipe/speckit/casa/docs/justificativa2.txt).
5. Re-run `unittest`, test live `POST /api/scan` against OWASP Juice Shop, commit, tag `sdd-074`, and push to `origin/main`.

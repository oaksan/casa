# Implementation Plan: Iteration 11 — Deep Automation & Justification for SCA-03

**Branch**: `[011-sca-03-deep-automation]` | **Date**: 2026-11-18 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/011-sca-03-deep-automation/spec.md)

## Summary

1. Implement `evaluate_sca03_container_os(repo)` in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py) to extract OS packages (`dpkg/status.d`) from the container image, add them to `output/sbom.cdx.json`, query OSV.dev (`Debian:13`), compute CVSS v3.1 scores (`>= 7.0`), filter out distribution `unimportant`/`will_not_fix` entries, and emit `CASA3-SCA-03` results to `output/sca-findings.sarif`.
2. Append `CONTROLE 03/61: SCA-03` to [`docs/justificativa.txt`](file:///home/user/felipe/speckit/casa/docs/justificativa.txt).
3. Update [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py), commit, tag `sdd-011`, and push `main` and `--tags` to `https://github.com/oaksan/casa`.

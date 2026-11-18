# Implementation Plan: Iteration 10 — Deep Automation & Justification for SCA-02

**Branch**: `[010-sca-02-deep-automation]` | **Date**: 2026-11-18 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/010-sca-02-deep-automation/spec.md)

## Summary

1. Replace the static 6-package `known_deprecated` dictionary for `SCA-02` in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py) with `evaluate_sca02_dependencies(repo, deps)`, which:
   - Parses `package-lock.json` (`resolved` and `integrity`) to verify canonical registry origin or digest pinning;
   - Queries `endoflife.date` API and `registry.npmjs.org` for EOL cycles and official deprecation notices;
   - Resolves GitHub repository URLs and queries the **OpenSSF Scorecard API** (`https://api.securityscorecards.dev/projects/github.com/<org>/<repo>`) for `Maintained < 5`;
   - Emits `CASA3-SCA-02` findings into `output/sca-findings.sarif`.
2. Append the complete academic and empirical justification for `SCA-02` to [`docs/justificativa.txt`](file:///home/user/felipe/speckit/casa/docs/justificativa.txt).
3. Add unit tests for `SCA-02` in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py), commit, tag `sdd-010`, and push `main` and `--tags` to `https://github.com/oaksan/casa`.

# Implementation Plan: Iteration 72 — Guide-Compliant Reference Tooling for SCA-02

**Branch**: `[072-sca-02-guide-tooling]` | **Date**: 2026-11-21 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/072-sca-02-guide-tooling/spec.md)

## Summary

1. Enhance `evaluate_sca02_dependencies` in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py):
   - Resolve exact installed versions (`v.get("version")`), `resolved` URLs, and `integrity` digests from `package-lock.json` for direct npm dependencies (instead of relying on raw `^`/`~` range versions in `package.json`), and detect untrusted `requirements*.txt` sources (`git+`, `--extra-index-url`, plain `http://`).
   - Expand `endoflife.date` mapping (`express`, `vue`, `react`, `nextjs`, `nuxt`, `django`, `sqlite`, `angular`, `bootstrap`, `moment`, `jquery`) with shared per-product caching, plus check `engines.node` against `endoflife.date/api/nodejs.json`.
   - Extend `OpenSSF Scorecard` (`Maintained >= 5`) and registry metadata inspection (`pypi.org/pypi/{pkg}/json` — inactive classifiers, yanked version, repository slug) to **PyPI** dependencies in addition to npm.
   - Bump `sca02_metadata_cache.json` schema key (`v2:`) to avoid stale v1 cache entries.
2. Add `test_iteration72_sca02_guide_tooling` in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py).
3. Record Iteration 72 (`CONTROLE 02/61: SCA-02`) in [`docs/justificativa2.txt`](file:///home/user/felipe/speckit/casa/docs/justificativa2.txt).
4. Re-run `unittest` and validate live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000` + `/home/user/felipe/speckit/juice-shop-master`).

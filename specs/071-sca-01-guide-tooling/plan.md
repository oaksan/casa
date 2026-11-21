# Implementation Plan: Iteration 71 — Guide-Compliant Reference Tooling for SCA-01

**Branch**: `[071-sca-01-guide-tooling]` | **Date**: 2026-11-21 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/071-sca-01-guide-tooling/spec.md)

## Summary

1. Install free official open-source reference binaries in `/home/user/.local/bin/`:
   - `syft` (Anchore) for CycloneDX 1.5 SBOM generation
   - `osv-scanner` (Google / OSV-SCALIBR) for OSV.dev / NVD lockfile & dependency vulnerability scanning + SARIF 2.1.0 export
2. Update `casa-assessment/casa_audit/scanner.py` (`SCA-01` and SBOM pipeline in `run_sca_checks`):
   - Add `SYFT_BIN` and `OSV_SCANNER_BIN` resolution + `generate_sbom_with_syft(...)` to emit `output/sbom.cdx.json` (`CycloneDX 1.5`) and extract the transitive `dependencies` graph.
   - Add `run_osv_scanner_for_sca01(...)` executing `osv-scanner scan source -r` (excluding `node_modules`, `.git`, `output`, `samples`, `frontend` build caches where appropriate, or scanning lockfiles/manifests cleanly) in both JSON and SARIF 2.1.0 (`output/osv-scanner.sarif`).
   - Enhance reachability with transitive dependency-graph tracing from reachable direct imports (`trace_transitive_reachability(...)`) alongside `analyze_package_reachability(...)`, plus CISA KEV matching (`fetch_cisa_kev_set()`).
   - Ensure full compatibility with `SCA-02`, `SCA-03`, `SCA-04`, and `SCA-05`, and preserve unit-test guarantees (no truncation or non-blocking leakage in logs).
3. Update `casa-assessment/tests/test_iteration1.py` and `docs/justificativa.txt` with Iteration 71 details and live OWASP Juice Shop empirical findings.
4. Run unit test suite (`unittest`) and execute live `POST /api/scan` against OWASP Juice Shop (`http://localhost:3000` + `/home/user/felipe/speckit/juice-shop-master`).

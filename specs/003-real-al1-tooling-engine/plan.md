# Implementation Plan: Iteration 3 — Real AL1 Tooling & Active DAST/SAST/SCA Engine

**Branch**: `[003-real-al1-tooling-engine]` | **Date**: 2026-11-16 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/003-real-al1-tooling-engine/spec.md)

## Summary

Upgrade [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py) from lightweight regex/HTTP stubs to a full multi-stage execution engine producing the three canonical CASA 3.0 open evidence artifacts on disk (`casa-assessment/output/`):
1. **`sbom.cdx.json`** (CycloneDX 1.5 SBOM) + live **OSV.dev** batch API query (`https://api.osv.dev/v1/querybatch`) for `SCA-01..05`.
2. **`semgrep-sast.sarif`** (OASIS SARIF 2.1.0) via **`/home/user/.local/bin/semgrep`** (`1.180.0`) with custom AST ruleset [`casa-assessment/rules/casa3_al1_sast.yml`](file:///home/user/felipe/speckit/casa/casa-assessment/rules/casa3_al1_sast.yml) for `SAST-01..13`.
3. **`dast-capture.har`** (W3C HAR 1.2) from active multi-route HTTP/TLS/Auth/Injection/OAuth probes for `TLS-01..06`, `CFG-01..11`, `AUT-01..08`, `AZI-01..06`, and `OAU-01..09`.

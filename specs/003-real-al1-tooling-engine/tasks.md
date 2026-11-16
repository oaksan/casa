---
description: "Task list for Iteration 3: Real AL1 Tooling & Active DAST/SAST/SCA Engine"
---

# Tasks: Iteration 3 — Real AL1 Tooling & Active DAST/SAST/SCA Engine

- [x] T301 Create Semgrep AST ruleset mapped to `SAST-01..13` in `casa-assessment/rules/casa3_al1_sast.yml`
- [x] T302 Implement CycloneDX 1.5 SBOM generator and live OSV.dev batch vulnerability API client for `SCA-01..05` in `casa-assessment/casa_audit/scanner.py`
- [x] T303 Implement real Semgrep subprocess runner and SARIF 2.1.0 exporter (`output/semgrep-sast.sarif`) for `SAST-01..13` in `casa-assessment/casa_audit/scanner.py`
- [x] T304 Implement active multi-route HTTP/TLS/Auth/SQLi/LFI/OAuth probe engine and W3C HAR 1.2 recorder (`output/dast-capture.har`) for `TLS`, `CFG`, `AUT`, `AZI`, `OAU`, and `WHK`
- [x] T305 Validate full AL1 scan against live OWASP Juice Shop (`http://localhost:3000` & `/home/user/felipe/speckit/juice-shop-master`)

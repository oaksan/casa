# Feature Specification 106 — AUT-01 Guide-Compliant Tooling (`SecLists` + Replay Harness)

## Control Covered
- **ID:** `AUT-01`
- **Title:** No default, shared or vendor-supplied credentials accepted
- **External Reference:** ASVS V2.5.4 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** **`SecLists`** curated default credential corpus (`casa-assessment/rules/seclists_aut01_default_creds.txt`) merged with product-derived vendor defaults from `CFG-03` version/product disclosure + scripted replay harness generating SARIF 2.1.0 and redacted HAR 1.2 (`output/aut01-replayed.har` & `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Zero credential pairs from the combined SecLists + product-vendor corpus authenticate on any active login surface.
  - **FAIL:** `>= 1` credential pair authenticates and yields a session token or `Set-Cookie`.

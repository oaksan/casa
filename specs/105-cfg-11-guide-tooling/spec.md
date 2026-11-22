# Feature Specification 105 — CFG-11 Guide-Compliant Tooling (`dnsx` + `nuclei`)

## Control Covered
- **ID:** `CFG-11`
- **Title:** No dangling DNS record on any declared host or its CNAME chain permits subdomain takeover
- **External Reference:** ASVS V10.3.3 (L1); CWE-350 | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** ProjectDiscovery **`dnsx`** (`v1.3.1` DNS & CNAME/A/AAAA resolution + `dig` fallback) + ProjectDiscovery **`nuclei`** (`v3.11.1` with validated takeover template `rules/nuclei_cfg11/takeover-fingerprints.yaml`).
- **Evidence:** DAST findings in SARIF 2.1.0 (`dast-findings.sarif`), Nuclei SARIF/JSONL (`nuclei-cfg11.sarif`, `nuclei-cfg11.jsonl`), `dnsx` JSON (`dnsx-cfg11.json`), and HTTP HAR 1.2 (`dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** Zero DNS records on any declared host or hop in its CNAME chain match an unclaimed-provider takeover condition (`NXDOMAIN` dangling CNAME or unclaimed provider error banner).
  - **FAIL:** `>= 1` dangling CNAME record or unclaimed-provider takeover banner detected.

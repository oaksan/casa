# Feature Specification 116 — AZI-03 Guide-Compliant Tooling (`sqlmap` + `OWASP ZAP SQLi 40018/40024` + `NoSQL Differential/Operator Scanner`)

## Control Covered
- **ID:** `AZI-03`
- **Title:** No SQL or NoSQL injection
- **External Reference:** ASVS V5.3.4 (L1); CWE-89, CWE-943 | **Profile:** `All`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Real **`sqlmap`** (`1.10.11`) authenticated scan + **OWASP ZAP** active SQLi rules (`40018`, `40024`) + authenticated **SQLi/NoSQL `$where` and JSON operator (`$ne`, `$regex`, `$gt`) differential harness**, producing SARIF 2.1.0 (`CASA3-AZI-03`), structured JSON (`output/azi03-sqli-nosql-audit.json`, `output/azi03-sqlmap-report.json`), and redacted HAR 1.2 (`output/azi03-replayed.har` + `output/dast-capture.har`).
- **Verification Criteria:**
  - **PASS:** `sqlmap` reports zero injectable parameters, OWASP ZAP reports zero SQLi alerts, and no SQLi/NoSQL payload alters query result sets or bypasses authentication.
  - **FAIL:** `>= 1` injectable parameter reported by `sqlmap`/ZAP/differential SQLi **or** `>= 1` NoSQL payload alters query results or bypasses authentication.

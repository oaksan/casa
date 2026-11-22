# Feature Specification 098 — CFG-04 Guide-Compliant Tooling (`csp-evaluator`)

## Control Covered
- **ID:** `CFG-04`
- **Title:** Content-Security-Policy enforced; `script-src` excludes `unsafe-inline` and `unsafe-eval`
- **External Reference:** ASVS V14.4.3 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Google `csp-evaluator` (`csp_evaluator@1.1.8` via Node.js).
- **Evidence:** DAST findings in SARIF 2.1.0 (`dast-findings.sarif`), HAR 1.2 (`dast-capture.har`), and `csp-evaluator` JSON evaluation report (`csp-evaluator.json`).
- **Verification Criteria:**
  - **PASS:** Every HTML route carries an enforcing `Content-Security-Policy` header and `csp-evaluator` confirms that effective `script-src` (or `default-src` fallback) defines a valid source list without `unsafe-inline`, `unsafe-eval`, `*`, or `data:`.
  - **FAIL:** Enforcing CSP absent on >= 1 HTML response (including `Report-Only`-only responses), or effective `script-src`/`default-src` missing, or any forbidden token detected.

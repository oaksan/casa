# Feature Specification 107 — AUT-02 Guide-Compliant Tooling (`SP 800-90B` + `200-Sample Harness`)

## Control Covered
- **ID:** `AUT-02`
- **Title:** Session tokens possess ≥ 64 bits of entropy
- **External Reference:** ASVS V3.2.2 (L1) | **Profile:** `Web_Application`

## Official Guide Alignment (`CASA 3.0 (AL1) Test Guide.md`)
- **Reference Tooling:** Scripted 200-login session-token collector + **NIST SP 800-90B** entropy estimator suite (Most Common Value `§6.3.1` with 99% upper confidence bound, positional estimator across token characters/bytes, and collision uniqueness audit) outputting SARIF 2.1.0, `output/aut02-sp800-90b.json`, and redacted HAR 1.2 (`output/aut02-replayed.har`).
- **Verification Criteria:**
  - **PASS:** All 200 freshly authenticated session tokens are distinct **and** conservative NIST SP 800-90B min-entropy estimate `>= 64.0` bits.
  - **FAIL:** Any duplicate/colliding token among the 200 samples **or** estimated SP 800-90B min-entropy `< 64.0` bits.

# SDD Iteration 045 Spec: AUT-02 Deep Automation

## Control Under Audit
- **ID:** `AUT-02`
- **Requirement:** Session tokens possess >= 64 bits of entropy (`OWASP ASVS V3.2.2 (L1)`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner calculated character-frequency Shannon entropy over a single JWT signature, producing a false `PASS` without collecting 200 session tokens.
2. Failed to detect exact duplicate JWT issuance caused by 1-second `iat` timestamps without random `jti` nonces.
3. Lacked NIST SP 800-90B MCV min-entropy computation and `CASA3-AUT-02` SARIF 2.1.0 emission.

## Requirements
- Collect 200 session tokens from fresh authentications (`POST /rest/user/login`) over persistent HTTP keep-alive connection.
- Require `unique_tokens == 200` AND NIST SP 800-90B Most-Common-Value (MCV) min-entropy `>= 64.0` bits.
- Emit `CASA3-AUT-02` findings to `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

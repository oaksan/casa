# Specification — SDD 068: WHK-02 Deep Automation

- **Control ID:** `WHK-02`
- **Title:** Payloads are authenticated with HMAC-SHA256 or stronger, verified using a timing-safe comparison
- **External References:** CASA v2.1.1 §7.2.1, §7.2.2; CWE-208
- **Applicable Profile:** `Web_Application`

## Requirements
1. Deliver 4 invalid-signature webhook replay probes per discovered receiver (`absent_signature`, `truncated_signature`, `modified_signature`, `foreign_key_signature`) using `http_probe` (HAR 1.2).
2. Inspect webhook verification source call sites for MAC strength (`HMAC-SHA256` or stronger, flagging SHA-1/MD5) and constant-time comparison APIs (`crypto.timingSafeEqual`, `hmac.compare_digest`, `MessageDigest.isEqual`, `subtle.ConstantTimeCompare`), flagging variable-time `===`/`==`/`Buffer.compare` (`CWE-208`).
3. Support per-clause `Not_Covered` tracking when source code is absent per Test Guide rules.
4. Emit `CASA3-WHK-02` findings to `output/dast-findings.sarif` (SARIF 2.1.0).

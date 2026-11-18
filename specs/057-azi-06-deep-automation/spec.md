# SDD Iteration 057 Spec: AZI-06 Deep Automation

## Control Under Audit
- **ID:** `AZI-06`
- **Requirement:** No open redirect or unvalidated forward; HTTP parameter pollution handled safely (`OWASP ASVS V5.1.5, V5.1.1 (L1); CWE-601`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner relied strictly on static substring check inside `routes/redirect.ts` and `lib/insecurity.ts` without firing HTTP `NoRedirect` probes.
2. Never tested duplicated-parameter HTTP Parameter Pollution (HPP) authorization bypasses (`?to=evil&to=allowlisted`).
3. Missing `CASA3-AZI-06` SARIF 2.1.0 entries and redacted HAR 1.2 artifact links.

## Requirements
- Execute `follow_redirects=False` probes against `/redirect` (`direct`, `//`, `?allowlisted`, `@evil`) checking parsed hostname of `Location` and `meta-refresh` against allowed hosts.
- Run differential duplicated-parameter HPP probes comparing baseline `406`/`401`/`403` vs duplicated parameter outcomes.
- Emit `CASA3-AZI-06` (`CWE-601`, `CWE-235`) findings to `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

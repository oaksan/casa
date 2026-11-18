# SDD Iteration 042 Spec: CFG-10 Deep Automation

## Control Under Audit
- **ID:** `CFG-10`
- **Requirement:** No administrative interface reachable without authentication (`CWE-306; ADA-defined`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner only probed `/rest/admin/application-configuration` once instead of differential authenticated-vs-unauthenticated replay.
2. Missing administrative/operational wordlist comparison and LCS normalized line similarity ratio (`>= 0.90`) calculation.
3. Missing `CASA3-CFG-10` SARIF 2.1.0 entries in `output/dast-findings.sarif`.

## Requirements
- Replay the authenticated route set (6 routes) with credentials removed.
- Probe 12 administrative/operational paths both with and without credentials and compute normalized LCS line similarity (`difflib.SequenceMatcher`), filtering generic SPA fallback responses (`<app-root>`).
- Fail when any authenticated route accepts unauthenticated replay or any wordlist path returns 2xx unauthenticated with `LCS >= 0.90`, emitting `CASA3-CFG-10` to `output/dast-findings.sarif`.

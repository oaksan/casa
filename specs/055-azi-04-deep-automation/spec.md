# SDD Iteration 055 Spec: AZI-04 Deep Automation

## Control Under Audit
- **ID:** `AZI-04`
- **Requirement:** No OS command injection (`OWASP ASVS V5.3.8 (L1); CWE-78`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner produced a conflated static `FAIL` by grepping `vm.runInContext` (`CWE-94` JS sandbox already covered by `SAST-10`) without executing any OS command injection HTTP probes.
2. Lacked an ephemeral out-of-band HTTP callback listener, shell output marker regexes, and `CASA3-AZI-04` SARIF 2.1.0 integration.

## Requirements
- Start an ephemeral HTTP out-of-band callback listener (`CmdCallbackHandler`) and send 20 authenticated shell injection payloads (`; id; curl`, `$(curl) $(id)`, backtick `id`, `| id`) across 5 parameter surfaces (`query:q`, `path:id`, `json:email`, `form:username`, `json:orderLinesData`).
- Inspect responses for OS command output markers (`uid=... gid=...`, `root:x:0:0:`, etc.) and live callbacks, emitting `CASA3-AZI-04` into `output/dast-findings.sarif` alongside redacted `output/dast-capture.har`.

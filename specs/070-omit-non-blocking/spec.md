# Specification — SDD 070: Omit Non-blocking Findings Across All Controls

## Goal
Ensure that automated CASA 3.0 AL1 control logs report only normatively relevant blocking findings (`error`-level criteria per Test Guide), omitting `Non-blocking` and `Informational` advisory lists across all 61 controls while preserving full internal triage (OSV.dev + CVSS v3.1 + CISA KEV + call-graph reachability + OS distribution status).

## Scope
- `SCA-01`: Omit `Non-blocking (CVSS < 7.0 or unreachable in call-graph)` (`FAIL`) and `Informational (CVSS < 7.0 or unreachable)` (`PASS`).
- `SCA-03`: Omit `Non-blocking OS Advisories` (`FAIL` & `PASS`).
- `TLS-04`: Omit `Informational: certificate expires in <30 days` warning suffix (`PASS`).
- Global regression test across all 61 control outputs in `tests/test_iteration1.py`.

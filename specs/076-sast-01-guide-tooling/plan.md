# Implementation Plan: Iteration 76 — Guide-Compliant Reference Tooling for SAST-01

**Branch**: `[076-sast-01-guide-tooling]` | **Date**: 2026-11-21 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/076-sast-01-guide-tooling/spec.md)

## Summary

1. Install official open-source `gitleaks` (`v8.30.1`) at `/home/user/.local/bin/gitleaks` (extracted from `zricethezav/gitleaks:latest`).
2. Enhance `evaluate_sast01_secrets_and_entropy` and `run_sast_checks` in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py):
   - Add `GITLEAKS_BIN` resolution and `run_gitleaks_for_sast(...)` using `[extend] useDefault = true` + triage allowlist (`node_modules`, `.git`, `logs`, `output`, `tests`, `*.spec.*`).
   - Generate native `output/gitleaks-sast01.sarif` (`SARIF 2.1.0`) + structured JSON findings with entropy & rule IDs, deduplicating with `Semgrep` & `Shannon` entropy checks (`data/static/users.yml`, `createHmac`, `[Op.like]`).
   - Run `gitleaks` concurrently with `semgrep` inside `run_sast_checks` to maintain fast overall scan time, and reference `gitleaks-sast01.sarif` in `SAST-01` Evidence.
3. Add `test_iteration76_sast01_guide_tooling` in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py).
4. Record `CONTROLE 06/61: SAST-01 (Iteração SDD 076)` in [`docs/justificativa2.txt`](file:///home/user/felipe/speckit/casa/docs/justificativa2.txt).
5. Run `unittest` and live `POST /api/scan` against OWASP Juice Shop, commit, tag `sdd-076`, and push to `origin/main`.

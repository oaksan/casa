# Feature Specification: Iteration 76 — Guide-Compliant Reference Tooling for Control SAST-01

**Feature Branch**: `[076-sast-01-guide-tooling]`

**Created**: 2026-11-21

**Status**: In Progress (Iteration 76)

**Input**: Align control `SAST-01` strictly with `CASA/CASA 3.0 (AL1) Test Guide.md` (`gitleaks` / `trufflehog`) for pattern + entropy secret detection across source, resources, build config, and shipped artifacts, validated live against OWASP Juice Shop.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Guide-Compliant Reference Tooling for SAST-01 (Priority: P1)

As a Master's researcher enforcing strict adherence to `CASA 3.0 (AL1) Test Guide.md`, I want control **`SAST-01`** (*"No hardcoded passwords, API keys, tokens or credentials in source, resources or build config"*) to execute the official open-source reference tool **`gitleaks`** (`v8.30.1`) across repository source, build config (`terraform`/`Dockerfile`/`config`), and shipped artifacts (`ftp/*`, `frontend/src/*`), exporting native `output/gitleaks-sast01.sarif` (`SARIF 2.1.0`) while applying automated false-positive triage (`logs/`, `node_modules/`, test specs, scanner fixtures) and combining with Shannon-entropy & pattern credential checks (`data/static/users.yml`, `createHmac`, `[Op.like]`) into `output/semgrep-sast.sarif`.

**Acceptance Scenarios**:

1. **Given** a target repository (`juice-shop-master`), **When** `evaluate_sast01_secrets_and_entropy` executes, **Then** it invokes `gitleaks dir` using official default rules (`useDefault = true`) plus triage allowlist, outputs `output/gitleaks-sast01.sarif`, detects hardcoded secrets across source, terraform/config, and frontend (`faucet.component.ts`), and merges them cleanly with `SAST-01` credential/entropy checks.
2. **Given** unit tests and live OWASP Juice Shop scan, **When** validated, **Then** `test_iteration76_sast01_guide_tooling` passes (`Gitleaks` binary verified, secret hit caught, test mock triaged out) and live `POST /api/scan` confirms `SAST-01` findings and SARIF artifacts.

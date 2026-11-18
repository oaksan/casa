# Implementation Plan: SDD Iteration 14 — Control SAST-01 Deep Automation & Justification

**Branch**: `014-sast-01-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/014-sast-01-deep-automation/spec.md`

## Summary

Aprimorar a automação do controle `SAST-01` combinando análise sintática via Semgrep AST (`rules/casa3_al1_sast.yml`) com um detector baseado em Entropia de Shannon e padrões multi-camada (`evaluate_sast01_secrets_and_entropy` em `casa_audit/scanner.py`) cobrindo código-fonte, recursos (`data/static/users.yml`), configuração e artefatos de frontend (`frontend/src/app/login/login.component.ts`), além de documentar os 37 achados empíricos no OWASP Juice Shop em `docs/justificativa.txt`.

## Technical Context

- **Language/Version**: Python 3.12 + Semgrep 1.180.0
- **Primary Dependencies**: `math`, `re`, `json`, `subprocess`, `pathlib`
- **Target Project Analyzed**: OWASP Juice Shop v20.3.0 (`/home/user/felipe/speckit/juice-shop-master`)
- **Documentation Artifact**: `/home/user/felipe/speckit/casa/docs/justificativa.txt`

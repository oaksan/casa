# Implementation Plan: SDD Iteration 15 — Control SAST-02 Deep Automation & Justification

**Branch**: `015-sast-02-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/015-sast-02-deep-automation/spec.md`

## Summary

Aprimorar a automação do controle `SAST-02` combinando a regra Semgrep AST (`CASA3-SAST-02-committed-private-key`) com o inspetor de keystores, arquivos de chave, blocos PEM e sementes BIP-39 (`evaluate_sast02_trust_material_and_keys` em `casa_audit/scanner.py`), além de documentar os 7 achados empíricos no OWASP Juice Shop em `docs/justificativa.txt`.

## Technical Context

- **Language/Version**: Python 3.12 + Semgrep 1.180.0 + Git CLI
- **Primary Dependencies**: `re`, `json`, `subprocess`, `pathlib`
- **Target Project Analyzed**: OWASP Juice Shop v20.3.0 (`/home/user/felipe/speckit/juice-shop-master`)
- **Documentation Artifact**: `/home/user/felipe/speckit/casa/docs/justificativa.txt`

# Implementation Plan: SDD Iteration 25 — Control SAST-12 Deep Automation & Justification

**Branch**: `025-sast-12-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/025-sast-12-deep-automation/spec.md`

## Summary

Implementar `evaluate_sast12_secrets_management_and_iac(repo)` em `casa-assessment/casa_audit/scanner.py` (inventário de SDKs de Secrets Manager, auditoria Terraform/config e inspeção Docker `.Config.Env` + arquivos de segredo assados na imagem) e expandir `CASA3-SAST-12-hardcoded-config-secrets` em `rules/casa3_al1_sast.yml`, documentando os 6 achados no OWASP Juice Shop em `docs/justificativa.txt`.

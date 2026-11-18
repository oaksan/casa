# Implementation Plan: SDD Iteration 20 — Control SAST-07 Deep Automation & Justification

**Branch**: `020-sast-07-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/020-sast-07-deep-automation/spec.md`

## Summary

Implementar a verificação híbrida completa do `SAST-07` (Semgrep AST para auto-binders irrestritos em `rules/casa3_al1_sast.yml` + sonda ativa `evaluate_sast07_mass_assignment_probe` em `casa_audit/scanner.py` enviando `"role": "admin"`), validar contra o OWASP Juice Shop (`http://localhost:3000`) e documentar em `docs/justificativa.txt`.

# Implementation Plan: SDD Iteration 18 — Control SAST-05 Deep Automation & Justification

**Branch**: `018-sast-05-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/018-sast-05-deep-automation/spec.md`

## Summary

Expandir `CASA3-SAST-05-weak-password-kdf` em `rules/casa3_al1_sast.yml` para capturar sinks de persistência de senha (`models/user.ts:73`), implementar `evaluate_sast05_password_kdf(repo)` em `casa_audit/scanner.py` para auditar os pisos numéricos do NIST SP 800-63B §5.1.1.2 (`Argon2id`, `scrypt`, `bcrypt`, `PBKDF2`) e salts estáticos, e documentar em `docs/justificativa.txt`.

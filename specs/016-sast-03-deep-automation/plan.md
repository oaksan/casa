# Implementation Plan: SDD Iteration 16 — Control SAST-03 Deep Automation & Justification

**Branch**: `016-sast-03-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/016-sast-03-deep-automation/spec.md`

## Summary

Expandir as regras Semgrep AST do controle `SAST-03` em `casa-assessment/rules/casa3_al1_sast.yml` para cobrir todas as variantes OpenSSL/Node.js, `CryptoJS` e Python (`PyCryptodome`/`cryptography`) de cifras banidas (`DES`, `3DES`, `RC4`, `Blowfish`, `ECB`), validar com fixture positivo/negativo e documentar em `docs/justificativa.txt`.

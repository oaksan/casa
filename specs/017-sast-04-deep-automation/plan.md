# Implementation Plan: SDD Iteration 17 — Control SAST-04 Deep Automation & Justification

**Branch**: `017-sast-04-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/017-sast-04-deep-automation/spec.md`

## Summary

Expandir as regras Semgrep AST do controle `SAST-04` em `casa-assessment/rules/casa3_al1_sast.yml` para cobrir `createHmac('md5'|'sha1')`, `CryptoJS.MD5/SHA1`, fluxos `$SEC.hash(...)` para sorvedouros de segurança e Python (`hashlib.md5/sha1`, `hmac.new`), validar no OWASP Juice Shop (15 achados) e documentar em `docs/justificativa.txt`.

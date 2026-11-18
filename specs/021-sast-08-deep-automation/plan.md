# Implementation Plan: SDD Iteration 21 — Control SAST-08 Deep Automation & Justification

**Branch**: `021-sast-08-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/021-sast-08-deep-automation/spec.md`

## Summary

Expandir as regras Semgrep AST do controle `SAST-08` em `casa-assessment/rules/casa3_al1_sast.yml` para cobrir tanto SQL Injection (interpolação/concatenação) quanto NoSQL Injection (`$where` em MarsDB/MongoDB) e Python (`cursor.execute`), validar no OWASP Juice Shop (13 achados) e documentar em `docs/justificativa.txt`.

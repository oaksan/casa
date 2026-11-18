# Implementation Plan: SDD Iteration 24 — Control SAST-11 Deep Automation & Justification

**Branch**: `024-sast-11-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/024-sast-11-deep-automation/spec.md`

## Summary

Converter `SAST-11` em `casa-assessment/rules/casa3_al1_sast.yml` para `mode: taint` do Semgrep cobrindo parâmetros HTTP, filenames de upload e entradas de arquivo `.zip` (`entry.path` / Zip Slip) até APIs de I/O em JS/TS e Python, validar no OWASP Juice Shop (10 achados reais) e documentar em `docs/justificativa.txt`.

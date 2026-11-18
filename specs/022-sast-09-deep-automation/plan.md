# Implementation Plan: SDD Iteration 22 — Control SAST-09 Deep Automation & Justification

**Branch**: `022-sast-09-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/022-sast-09-deep-automation/spec.md`

## Summary

Expandir as regras Semgrep do controle `SAST-09` em `rules/casa3_al1_sast.yml` para capturar desserialização insegura de XML/XXE (`libxml2.XmlDocument.fromString`, `XML_PARSE_NOENT`, `XML_PARSE_DTDLOAD`), YAML em `vm.runInContext` (`routes/fileUpload.ts:114`) e equivalentes Python (`pickle`, `marshal`, `yaml.load`), adicionar deduplicação por linha em `casa_audit/scanner.py`, e documentar em `docs/justificativa.txt`.

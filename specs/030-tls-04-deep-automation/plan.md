# Implementation Plan: SDD Iteration 30 — Control TLS-04 Deep Automation & Justification

**Branch**: `030-tls-04-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/030-tls-04-deep-automation/spec.md`

## Summary

Implementar `probe_x509_certificate()` em `casa-assessment/casa_audit/scanner.py` (validação PKIX contra Public Root Store, matching CN/SAN, validade temporal + aviso `< 30 dias`), persistir `.certificate` em `output/tls-scan.json`, validar no OWASP Juice Shop (`http://localhost:3000`) e documentar em `docs/justificativa.txt`.

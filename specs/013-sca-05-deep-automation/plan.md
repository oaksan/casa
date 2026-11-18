# Implementation Plan: SDD Iteration 13 — Control SCA-05 Deep Automation & Justification

**Branch**: `013-sca-05-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/013-sca-05-deep-automation/spec.md`

## Summary

Aprofundar a automação do controle `SCA-05` em `casa-assessment/casa_audit/scanner.py` implementando a varredura multi-manifesto (`package.json`, `frontend/package.json`, `ftp/package.json.bak`), detecção de advisories `MAL-*` e comprometimento de mantenedor no OSV.dev, algoritmo de distância de edição de Levenshtein (`d == 1`) + sufixo de linguagem (`-js`) contra pacotes Top-10k canônicos, e verificação em tempo real de disjunção de mantenedores via `registry.npmjs.org`, além de documentar o resultado prático no OWASP Juice Shop em `docs/justificativa.txt`.

## Technical Context

- **Language/Version**: Python 3.12
- **Primary Dependencies**: `urllib.request`, `json`, `re`, `pathlib` (standard library)
- **External APIs**: OSV.dev (`/v1/querybatch`), npm Public Registry (`https://registry.npmjs.org/<pkg>`)
- **Target Project Analyzed**: OWASP Juice Shop v20.3.0 (`/home/user/felipe/speckit/juice-shop-master`)
- **Documentation Artifact**: `/home/user/felipe/speckit/casa/docs/justificativa.txt`

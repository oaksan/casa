# Implementation Plan: SDD Iteration 12 — Control SCA-04 Deep Automation & Justification

**Branch**: `012-sca-04-deep-automation` | **Date**: 2026-11-18 | **Spec**: `specs/012-sca-04-deep-automation/spec.md`

## Summary

Aprofundar a automação do controle `SCA-04` em `casa-assessment/casa_audit/scanner.py` implementando a validação de schema (`CycloneDX 1.5+` / `SPDX 2.3+`), verificação individual dos Elementos Mínimos da NTIA em metadados e componentes, e cálculo da diferença matemática de conjuntos (`Assessor_SBOM − Published_SBOM`), além de documentar a justificativa acadêmica e o resultado prático no OWASP Juice Shop em `docs/justificativa.txt`.

## Technical Context

- **Language/Version**: Python 3.12 + Docker CLI (`DOCKER_API_VERSION=1.44`)
- **Primary Dependencies**: `json`, `subprocess`, `pathlib`
- **Target Project Analyzed**: OWASP Juice Shop v20.3.0 (`/home/user/felipe/speckit/juice-shop-master` + `bkimminich/juice-shop:latest:/juice-shop/bom.json`)
- **Documentation Artifact**: `/home/user/felipe/speckit/casa/docs/justificativa.txt`

## Project Structure

```text
specs/012-sca-04-deep-automation/
├── spec.md
├── plan.md
└── tasks.md

docs/
└── justificativa.txt          # Added CONTROLE 04/61: SCA-04 (Iteração SDD 012)

casa-assessment/
├── casa_audit/
│   └── scanner.py             # Added evaluate_sca04_sbom_completeness() & CASA3-SCA-04 SARIF rule
└── tests/
    └── test_iteration1.py     # Added unit test for SCA-04 NTIA & Set Difference verification
```

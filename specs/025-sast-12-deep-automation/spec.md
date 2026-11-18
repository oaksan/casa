# Feature Specification: SDD Iteration 25 — Deep AL1 Automation & Academic Justification for Control SAST-12

**Feature Branch**: `025-sast-12-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 17/61: `SAST-12`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-12 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-12` (*"Server-side secrets are held in a managed secrets store, not in config files or environment baked into images"*) execute: (1) inventário de chamadas de SDKs de Secrets Manager (AWS/GCP/Azure/Vault), (2) auditoria de arquivos IaC/configuração (`.tf`, `.yml`, `.env`, `Dockerfile`) e (3) inspeção de variáveis `ENV` e artefatos de segredo assados nas camadas da imagem Docker (`bkimminich/juice-shop:latest`).

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop e verificar que o `SAST-12` reporta `0 call sites` de Secrets Manager SDK e os 6 achados em `lib/insecurity.ts`, `terraform/networking.tf:171`, `infrastructure/terraform/networking.tf:171` e `Dockerfile:38`.

## Requirements *(mandatory)*

- **FR-001**: `casa-assessment/casa_audit/scanner.py` DEVE implementar `evaluate_sast12_secrets_management_and_iac(repo)`.
- **FR-002**: `casa-assessment/rules/casa3_al1_sast.yml` DEVE expandir `CASA3-SAST-12-hardcoded-config-secrets` para incluir IaC/Terraform e HMAC.
- **FR-003**: O documento `docs/justificativa.txt` DEVE registrar a seção `CONTROLE 17/61: SAST-12 (Iteração SDD 025)`.
- **FR-004**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-025` e sincronizado no GitHub.

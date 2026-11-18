# Feature Specification: SDD Iteration 14 — Deep AL1 Automation & Academic Justification for Control SAST-01

**Feature Branch**: `014-sast-01-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 06/61: `SAST-01`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-01 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-01` (*"No hardcoded passwords, API keys, tokens or credentials in source, resources or build config"*) combine detecção baseada em padrões AST (`Semgrep`) e detecção baseada em Entropia de Shannon ($H(X)$) em código-fonte backend, recursos estáticos (`data/static/users.yml`), configuração e artefatos de frontend (`frontend/src/app/login/login.component.ts`), com triagem automatizada de falsos positivos.

**Why this priority**: O `CASA 3.0 (AL1) Test Guide.md` exige explicitamente o uso combinado de detectores baseados em padrão e baseados em entropia (*"using both pattern-based and entropy-based detectors"*) cobrindo `source, resources, build config and shipped artifacts`.

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop (`/home/user/felipe/speckit/juice-shop-master`) e verificar que as 37 credenciais e segredos hardcoded (em `lib/insecurity.ts`, `routes/login.ts`, `routes/verify.ts`, `data/static/users.yml` e `frontend/src/app/login/login.component.ts`) são detectados e gravados em `output/semgrep-sast.sarif`.

**Acceptance Scenarios**:

1. **Given** um repositório com código-fonte, recursos e artefatos de frontend, **When** `run_sast_checks` executa `SAST-01`, **Then** executa tanto a regra Semgrep AST `CASA3-SAST-01-hardcoded-secret` quanto o detector de Entropia de Shannon `evaluate_sast01_secrets_and_entropy()`.
2. **Given** cada segredo detectado, **When** `compute_shannon_entropy()` calcula $H(X)$ em bits/char, **Then** exclui mocks de testes (`.spec.ts`) e registra os achados confirmados (`verified=true`) no artefato `output/semgrep-sast.sarif`.

---

### User Story 2 - Academic Justification Documentation for Master's Defense (Priority: P1)

Como mestrando, preciso que a seção `CONTROLE 06/61: SAST-01 (Iteração SDD 014)` seja adicionada em `/home/user/felipe/speckit/casa/docs/justificativa.txt` explicando a base normativa do CASA 3.0 (`CWE-798`, `ASVS V2.10.4`), a formulação matemática da Entropia de Shannon e os 37 achados empíricos no OWASP Juice Shop.

**Independent Test**: Verificar a presença da seção `CONTROLE 06/61: SAST-01 (Iteração SDD 014)` em `docs/justificativa.txt`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: O scanner DEVE implementar `compute_shannon_entropy()` e `evaluate_sast01_secrets_and_entropy()` em `casa-assessment/casa_audit/scanner.py` e expandir a regra `CASA3-SAST-01-hardcoded-secret` em `casa-assessment/rules/casa3_al1_sast.yml`.
- **FR-002**: O scanner DEVE unificar os achados do Semgrep AST e do detector de Entropia de Shannon no artefato `output/semgrep-sast.sarif`.
- **FR-003**: O documento `docs/justificativa.txt` DEVE documentar a análise teórica e prática do `SAST-01`.
- **FR-004**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-014` e sincronizado no GitHub (`origin/main` + `--tags`).

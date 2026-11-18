# Feature Specification: SDD Iteration 12 — Deep AL1 Automation & Academic Justification for Control SCA-04

**Feature Branch**: `012-sca-04-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 04/61: `SCA-04`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SCA-04 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SCA-04` (*"A complete, machine-readable SBOM is published for the assessed build, and it matches an SBOM the assessor generates independently"*) valide o formato (`CycloneDX >= 1.5` ou `SPDX >= 2.3`), a presença de todos os Elementos Mínimos da NTIA em cada componente e a diferença matemática de conjuntos (`Assessor_SBOM − Published_SBOM == ∅`).

**Why this priority**: A implementação anterior apenas verificava se existia um arquivo `*sbom*.json` ou `*bom*.json` no diretório raiz, sem fazer o parsing do arquivo, sem inspecionar o `bom.json` publicado dentro da imagem de container (`/juice-shop/bom.json`), sem checar os Elementos Mínimos da NTIA e sem calcular a diferença de conjuntos contra o SBOM gerado pelo avaliador.

**Independent Test**: Executar `evaluate_sca04_sbom_completeness()` contra o OWASP Juice Shop (`/home/user/felipe/speckit/juice-shop-master` e `bkimminich/juice-shop:latest:/juice-shop/bom.json`) e contra fixtures de teste unitário (um SBOM válido e completo que retorna `PASS`, e um SBOM com ausência de fornecedor NTIA ou componente faltante que retorna `FAIL`).

**Acceptance Scenarios**:

1. **Given** um repositório e/ou imagem de container com SBOM publicado, **When** `evaluate_sca04_sbom_completeness` executa, **Then** valida se o formato é `CycloneDX >= 1.5` ou `SPDX >= 2.3`.
2. **Given** os componentes do SBOM publicado, **When** `SCA-04` valida os Elementos Mínimos da NTIA, **Then** verifica metadados (`timestamp`, `tools`/`authors`, `dependencies`) e, para cada componente, `supplier`/`author`/`publisher`/`group`, `name`, `version` e identificador único (`purl`/`cpe`/`bom-ref`/`SPDXID`).
3. **Given** o SBOM gerado independentemente pelo avaliador (`Assessor_SBOM`, contendo pacotes de aplicação e de SO) e o SBOM publicado (`Published_SBOM`), **When** `SCA-04` calcula `Assessor_SBOM − Published_SBOM`, **Then** reporta `FAIL` caso qualquer componente do avaliador esteja ausente ou com versão divergente no SBOM publicado.

---

### User Story 2 - Academic Justification Documentation for Master's Defense (Priority: P1)

Como mestrando, preciso que a seção `CONTROLE 04/61: SCA-04 (Iteração SDD 012)` seja adicionada em `/home/user/felipe/speckit/casa/docs/justificativa.txt` explicando a base normativa do CASA 3.0 (`ASVS V14.2.5`, `NTIA Minimum Elements`, `CycloneDX 1.5+`), a modelagem por Teoria dos Conjuntos ($S_{assessor} \setminus S_{pub} = \emptyset$) e os achados empíricos no OWASP Juice Shop.

**Independent Test**: Verificar a presença da seção `CONTROLE 04/61: SCA-04 (Iteração SDD 012)` em `docs/justificativa.txt`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: O scanner DEVE implementar `evaluate_sca04_sbom_completeness(repo, assessor_components, assessor_sbom_path)` em `casa-assessment/casa_audit/scanner.py`.
- **FR-002**: O scanner DEVE procurar o SBOM publicado tanto no repositório-fonte (`*sbom*.json`, `*bom*.json`, `*.cdx.json`, `*.spdx.json`, `ftp/*bom*.json`) quanto dentro da imagem de container associada (`/juice-shop/bom.json`, `/app/bom.json`).
- **FR-003**: O scanner DEVE validar `CycloneDX >= 1.5` ou `SPDX >= 2.3`, todos os Elementos Mínimos da NTIA e a diferença de conjuntos `Assessor_SBOM − Published_SBOM`, registrando falhas em `output/sca-findings.sarif` (`CASA3-SCA-04`).
- **FR-004**: O documento `docs/justificativa.txt` DEVE documentar a análise teórica e prática do `SCA-04`.
- **FR-005**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-012` e sincronizado no GitHub (`origin/main` + `--tags`).

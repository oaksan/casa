# Feature Specification: SDD Iteration 13 — Deep AL1 Automation & Academic Justification for Control SCA-05

**Feature Branch**: `013-sca-05-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 05/61: `SCA-05`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SCA-05 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SCA-05` (*"No dependency matches a known-malicious package advisory (typosquat, protestware, compromised maintainer)"*) consulte advisories de pacotes maliciosos (`MAL-*` e pacotes com mantenedor comprometido no OSV.dev) em todos os manifestos do projeto e aplique o predicado de typosquatting por distância de Levenshtein = 1 (e sufixos de linguagem `-js`) com verificação de mantenedores distintos na API do registro npm (`registry.npmjs.org`).

**Why this priority**: A implementação anterior olhava apenas o `package.json` raiz procurando o prefixo `MAL-`, deixando passar pacotes comprometidos históricos (`eslint-scope@3.7.2` / `GHSA-hxxf-q3w9-4xgw`) e pacotes de typosquatting em sub-manifestos (`ngy-cookie@6.0.0` em `frontend/package.json` contra `ngx-cookie`, e `epilogue-js@0.7` em `ftp/package.json.bak` contra `epilogue`).

**Independent Test**: Executar `evaluate_sca05_malicious_and_typosquat()` contra o OWASP Juice Shop (`/home/user/felipe/speckit/juice-shop-master`) e verificar que `eslint-scope@3.7.2`, `ngy-cookie@6.0.0` e `epilogue-js@0.7` são identificados e registrados em `output/sca-findings.sarif`.

**Acceptance Scenarios**:

1. **Given** os manifestos de dependências do repositório (`package.json`, `frontend/package.json`, `ftp/package.json.bak`), **When** `evaluate_sca05_malicious_and_typosquat` executa, **Then** consulta todas as dependências na API OSV.dev por advisories `MAL-*` e advisories de comprometimento de mantenedor/protestware.
2. **Given** cada pacote não pertencente à lista Top-10k canônica, **When** `SCA-05` calcula `compute_levenshtein_distance(pkg, canonical)` e sufixos (`-js`, `-node`), **Then** verifica no `registry.npmjs.org` se `Maintainers(pkg) ∩ Maintainers(canonical) == ∅` e sinaliza `FAIL` quando positivo.

---

### User Story 2 - Academic Justification Documentation for Master's Defense (Priority: P1)

Como mestrando, preciso que a seção `CONTROLE 05/61: SCA-05 (Iteração SDD 013)` seja adicionada em `/home/user/felipe/speckit/casa/docs/justificativa.txt` explicando a base normativa do CASA 3.0 (`OpenSSF Malicious Packages`, `CWE-1357`), a formulação matemática da distância de Levenshtein com disjunção de mantenedores e os 3 achados reais no OWASP Juice Shop.

**Independent Test**: Verificar a presença da seção `CONTROLE 05/61: SCA-05 (Iteração SDD 013)` em `docs/justificativa.txt`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: O scanner DEVE implementar `compute_levenshtein_distance()`, `fetch_npm_maintainers()` e `evaluate_sca05_malicious_and_typosquat()` em `casa-assessment/casa_audit/scanner.py`.
- **FR-002**: O scanner DEVE registrar as violações de `SCA-05` com `ruleId: "CASA3-SCA-05"` em `output/sca-findings.sarif`.
- **FR-003**: O documento `docs/justificativa.txt` DEVE documentar a análise teórica e prática do `SCA-05`.
- **FR-004**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-013` e sincronizado no GitHub (`origin/main` + `--tags`).

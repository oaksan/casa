# Feature Specification: SDD Iteration 15 — Deep AL1 Automation & Academic Justification for Control SAST-02

**Feature Branch**: `015-sast-02-deep-automation`  
**Created**: 2026-11-18  
**Status**: Implemented  
**Input**: User request: *"sim"* (Sequência de auditoria individual dos controles AL1 do CASA 3.0 para a proposta de mestrado — Controle 07/61: `SAST-02`).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Faithful CASA 3.0 AL1 Verification for SAST-02 (Priority: P1)

Como pesquisador de mestrado avaliando a automatizabilidade do CASA 3.0 AL1, preciso que o controle `SAST-02` (*"No private keys, certificates or trust material committed to the repository or shipped in artifacts"*) percorra a árvore de arquivos, o histórico Git e os artefatos distribuídos (`encryptionkeys/`, `ftp/`, raiz) em busca de arquivos de chave e keystore (`.key`, `.pem`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.kdbx`, `.pub`), blocos PEM `PRIVATE KEY` e sementes mnemônicas BIP-39 (`HDNodeWallet.fromPhrase`).

**Why this priority**: O `CASA 3.0 (AL1) Test Guide.md` exige percorrer o histórico do repositório e todos os artefatos distribuídos em busca de arquivos de keystore/certificados e blocos PEM `PRIVATE KEY` (*"walk every shipped artifact for key-store and certificate files and for PEM private-key blocks"*).

**Independent Test**: Executar `run_sast_checks()` contra o OWASP Juice Shop (`/home/user/felipe/speckit/juice-shop-master`) e verificar que os 7 materiais criptográficos/keystores (`lib/insecurity.ts:21`, `ctf.key`, `encryptionkeys/jwt.pub`, `encryptionkeys/premium.key`, `ftp/incident-support.kdbx` e `routes/checkKeys.ts:10-11`) são identificados e gravados em `output/semgrep-sast.sarif`.

**Acceptance Scenarios**:

1. **Given** um repositório com arquivos de chave e keystores distribuídos, **When** `evaluate_sast02_trust_material_and_keys()` executa, **Then** identifica arquivos `.key`, `.pem`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.kdbx` e `.pub` e valida suas assinaturas binárias/cabeçalhos.
2. **Given** arquivos de código-fonte e histórico Git, **When** `SAST-02` executa via Semgrep AST e inspeção léxica, **Then** identifica blocos PEM `PRIVATE KEY` e sementes BIP-39 que derivam chaves privadas.

---

### User Story 2 - Academic Justification Documentation for Master's Defense (Priority: P1)

Como mestrando, preciso que a seção `CONTROLE 07/61: SAST-02 (Iteração SDD 015)` seja adicionada em `/home/user/felipe/speckit/casa/docs/justificativa.txt` explicando a base normativa do CASA 3.0 (`CWE-321`, `CWE-798`, requisito inédito `ADA-defined`) e os 7 achados empíricos no OWASP Juice Shop.

**Independent Test**: Verificar a presença da seção `CONTROLE 07/61: SAST-02 (Iteração SDD 015)` em `docs/justificativa.txt`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: O scanner DEVE implementar `evaluate_sast02_trust_material_and_keys()` em `casa-assessment/casa_audit/scanner.py` e expandir a regra `CASA3-SAST-02-committed-private-key` em `casa-assessment/rules/casa3_al1_sast.yml`.
- **FR-002**: O scanner DEVE unificar os achados do Semgrep AST e do walker de keystores/chaves no artefato `output/semgrep-sast.sarif`.
- **FR-003**: O documento `docs/justificativa.txt` DEVE documentar a análise teórica e prática do `SAST-02`.
- **FR-004**: Ao final da iteração, o código DEVE ser commitado, marcado com a tag `sdd-015` e sincronizado no GitHub (`origin/main` + `--tags`).

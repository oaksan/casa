# Feature Specification: Iteration 7 — Full Untruncated Failing Findings in Evidence Logs & Dedicated `casa_backup` Directory

**Feature Branch**: `[007-untruncated-findings-and-backup-dir]`

**Created**: 2026-11-18

**Status**: Implemented (Iteration 7)

**Input**: User description: "implemente a iteracao 7 sdd para que os backups sejam agoras salvos em: /home/user/felipe/speckit/casa_backup, exemplo esta iteracao gerara o arquivo: /home/user/felipe/speckit/casa_backup/casa-007.zip e aproveite esta iteracao para implementar que seja exibido todos os findings de fail nas evidencias de cada controle. Exemplo do SCA-01 que ocultou 4 findings..."

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Complete Untruncated FAIL Findings in Evidence Logs (Priority: P1)

As an assessor or researcher reviewing the automated evidence log of any failing control (such as `SCA-01`, `SAST-01..13`, `AUT-08`, `AZI-02`, `OAU-07`) in the Assessment or Report view, I want **100% of the detected findings, advisory IDs, and file locations** to be listed in full without `... and X more` or `... (+X more)` truncation, so that the evidence record is complete and auditable for every control.

**Why this priority**: Scientific and audit completeness requires that every single vulnerable package, advisory ID, and source code finding be visible in the evidence log.

**Independent Test**: Run the automated AL1 scan against OWASP Juice Shop and verify that `SCA-01` lists all 16 vulnerable packages and all their advisory IDs in full, `SAST-06` lists all 10 Semgrep findings in full, and zero logs contain `... and` or `... (+`.

**Acceptance Scenarios**:

1. **Given** a control with multiple findings (e.g., `SCA-01` with 16 vulnerable packages or `SAST-06` with 10 Semgrep AST findings), **When** the automated scan log is generated, **Then** every single finding and advisory identifier is included in `log` with zero truncation.
2. **Given** any automated scan result across all 61 AL1 controls, **When** inspected by unit tests, **Then** no log string contains `... and ` or `... (+`.

---

### User Story 2 - Dedicated `/home/user/felipe/speckit/casa_backup` Archive Directory (Priority: P1)

As the project owner, I want all per-iteration rollback ZIP archives to be stored in `/home/user/felipe/speckit/casa_backup/casa-NNN.zip` (e.g., `/home/user/felipe/speckit/casa_backup/casa-007.zip`), keeping the parent workspace directory organized.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-701**: Remove all list-slicing truncations (`[:12]`, `[:8]`, `[:5]`, `[:4]`, `[:3]`, `[:120]`) and `"more"` summary suffixes from `casa-assessment/casa_audit/scanner.py` across SCA (`SCA-01`), SAST (`SAST-01..13`), Auth (`AUT-08`), Injection (`AZI-02`), and OAuth (`OAU-07`).
- **FR-702**: Update `.specify/memory/constitution.md` (v1.3.0) to mandate saving per-iteration rollback archives in `/home/user/felipe/speckit/casa_backup/casa-NNN.zip`.
- **FR-703**: Add unit test assertions in `casa-assessment/tests/test_iteration1.py` verifying that no scan output contains truncation markers (`"... and "`, `"... (+"`).

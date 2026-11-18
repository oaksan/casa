# Feature Specification: Iteration 10 — Deep Automation & Academic Justification for Control SCA-02

**Feature Branch**: `[010-sca-02-deep-automation]`

**Created**: 2026-11-18

**Status**: Implemented (Iteration 10)

**Input**: User request to implement SDD Iteration 10 auditing, enhancing, and justifying control `SCA-02` in `/docs/justificativa.txt` with empirical OWASP Juice Shop results.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Full CASA 3.0 Compliance for Automated Control SCA-02 (Priority: P1)

As a Master's researcher defending the automation of CASA 3.0 AL1, I want control **`SCA-02`** (*"No component is end-of-life, unmaintained, or sourced from an untrusted repository"*) to implement all three normative checks required by `CASA 3.0 (AL1) Test Guide.md`:
1. **Lockfile Registry Resolution**: Verify in `package-lock.json` that every direct dependency resolves from the canonical public registry (`https://registry.npmjs.org/`) or a digest-pinned (`sha512-...`/`sha256-...`) HTTPS mirror.
2. **Published End-of-Life & Deprecation Verification**: Query `endoflife.date` (`https://endoflife.date/api/<product>.json`) and registry metadata (`deprecated` warnings and legacy major branch EOL status).
3. **OpenSSF Scorecard Maintainer Activity Signal**: Query the official OpenSSF Scorecard API (`https://api.securityscorecards.dev/projects/github.com/<org>/<repo>`) and verify `Maintained >= 5`.

**Acceptance Scenarios**:

1. **Given** a target repository (`juice-shop-master`), **When** `SCA-02` runs, **Then** it inspects all direct dependencies against the lockfile registry policy, `endoflife.date` / npm deprecation notices, and the OpenSSF Scorecard `Maintained` metric (`< 5` fails), recording findings in `output/sca-findings.sarif` (`CASA3-SCA-02`).
2. **Given** `/docs/justificativa.txt`, **When** updated in Iteration 10, **Then** it includes a complete section for `CONTROLE 02/61: SCA-02` with CASA 3.0 normative grounding, technical improvements, and empirical OWASP Juice Shop results.

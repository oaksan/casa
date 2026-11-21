# Feature Specification: Iteration 72 — Guide-Compliant Reference Tooling for Control SCA-02

**Feature Branch**: `[072-sca-02-guide-tooling]`

**Created**: 2026-11-21

**Status**: In Progress (Iteration 72)

**Input**: Align control `SCA-02` strictly with `CASA/CASA 3.0 (AL1) Test Guide.md` (`OpenSSF Scorecard`, `endoflife.date`, lockfile registry resolution) across npm and PyPI manifests/lockfiles, and validate live against OWASP Juice Shop.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Guide-Compliant Reference Tooling for SCA-02 (Priority: P1)

As a Master's researcher enforcing strict adherence to `CASA 3.0 (AL1) Test Guide.md`, I want control **`SCA-02`** (*"No component is end-of-life, unmaintained, or sourced from an untrusted repository"*) to validate every direct dependency using:
1. Exact lockfile version & source registry resolution (`package-lock.json` canonical `registry.npmjs.org` or HTTPS mirror pinned by digest; non-canonical `git+`/`file:`/`http:` URLs flagged in `requirements*.txt` and lockfiles).
2. **`endoflife.date`** API across an expanded ecosystem product catalog (`angular`, `bootstrap`, `moment`, `jquery`, `express`, `vue`, `react`, `nextjs`, `nuxt`, `django`, `sqlite`, plus declared `engines.node`) alongside npm deprecation / PyPI inactive classifiers & yanked releases.
3. **`OpenSSF Scorecard`** API (`Maintained >= 5`) across **both npm and PyPI** direct dependencies, emitting `CASA3-SCA-02` findings into `output/sca-findings.sarif` alongside the Syft-generated `CycloneDX 1.5` SBOM (`output/sbom.cdx.json`).

**Acceptance Scenarios**:

1. **Given** a target repo with `package-lock.json` (like `juice-shop-master`) or `requirements*.txt`, **When** `evaluate_sca02_dependencies` executes, **Then** it resolves exact lockfile versions, validates registry provenance, queries `endoflife.date` (with product caching), and evaluates `OpenSSF Scorecard` `Maintained < 5` for both npm and PyPI packages.
2. **Given** a live scan against OWASP Juice Shop, **When** `SCA-02` completes, **Then** every direct dependency violation (EOL/Deprecated, `Maintained < 5`, or untrusted registry) is logged without truncation and written to `casa-assessment/output/sca-findings.sarif`.
3. **Given** `docs/justificativa2.txt`, **When** updated, **Then** it records `CONTROLE 02/61: SCA-02 (Iteração SDD 072)` with technical improvements and empirical Juice Shop results.

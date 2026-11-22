# SDD 082: Guide-Compliant Reference Tooling for SAST-07 (`semgrep` + `ZAP` / Lab-Account Mass Assignment Update & Read-Back — Burp Suite Free Alternative)

## Control Reference
- **Control ID**: `SAST-07`
- **Guide Requirement**: Frameworks protect against mass assignment / unsafe auto-binding (`Zero error-level unrestricted-binder findings, and no injected privileged field reads back as changed`).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`, `ZAP`, `Burp Suite` *(paid Burp Suite replaced exclusively by free `semgrep` + `OWASP ZAP` + Lab-Account HTTP Update/Read-Back Probe)*.
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-07-mass-assignment*` rules in `casa-assessment/rules/casa3_al1_sast.yml` across `TS/JS` (`finale.resource`, `epilogue.resource`, Sequelize/Mongoose/TypeORM/spread `{ ...req.body }`, `Object.assign($U, req.body)`), `Python` (`**req.data`, `**req.json`, Django `ModelForm` `fields = "__all__"`, `setattr` over `request.json`), `Java` (`BeanUtils.copyProperties`, Spring `@RequestBody`/`@ModelAttribute`), and `Go` (`ShouldBind`/`BindJSON`), at `severity: ERROR`.
2. Upgrade `evaluate_sast07_mass_assignment_probe` in `casa-assessment/casa_audit/scanner.py` to:
   - Execute full Lab-Account registration + login (`Bearer` + `Cookie: token=...`) + privileged-field injection (`role: "admin"`, `isAdmin: true`) via update endpoints (`PUT`/`PATCH`) and **verified read-back** (`GET /api/Users/{id}`, `/rest/user/whoami`, `/api/profile`),
   - Correlate any `OWASP ZAP` mass-assignment/parameter-tampering SARIF findings (`output/dast-findings.sarif`),
   - Append confirmed active mass-assignment findings into `output/semgrep-sast.sarif` (`CASA3-SAST-07-active-mass-assignment`, `level: "error"`).
3. Add `evaluate_sast07_framework_binding(repo)` delegating to `_evaluate_semgrep_control_sarif(repo, "SAST-07")`, enforce strict `ERROR`-level gating, and cite `OWASP ZAP` + Lab-Account Probe (free substitute for commercial `Burp Suite`) in `SAST-07` tool metadata.
4. Add `test_iteration82_sast07_guide_tooling`, test live against OWASP Juice Shop (`FAIL` confirming both static `server.ts:529` `finale.resource` and live `POST /api/Users/` + `GET /api/Users/{id}` read-back of `"role": "admin"`), document in `docs/justificativa2.txt`, commit, tag `sdd-082`, and push to GitHub.

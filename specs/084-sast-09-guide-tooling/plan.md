# Plan: SDD 084 — SAST-09 Guide Tooling (`semgrep` CWE-502)

1. Expand `CASA3-SAST-09-unsafe-deserialization*` in `casa-assessment/rules/casa3_al1_sast.yml` across `TS/JS`, `Python`, `Java`, `PHP`, and `C#/.NET` (respecting `SafeLoader`, `allowed_classes => false`, `ObjectInputFilter`, and HMAC integrity checks), and validate with `semgrep --validate`.
2. Update `casa-assessment/casa_audit/scanner.py` in one consolidated batch: add `evaluate_sast09_deserialization(repo)`, enforce `ERROR`-level gating for `SAST-09`, and set `SAST-09` tool label.
3. Add `test_iteration84_sast09_guide_tooling` in `casa-assessment/tests/test_iteration1.py` validating `PASS` (`yaml.SafeLoader`, `ObjectInputFilter`, `allowed_classes => false`, HMAC-verified `pickle.loads`, `JSON_SCHEMA`) and multi-language `FAIL` (`TS`, `Python`, `Java`, `PHP`, `C#`).
4. Run full unittest suite to completion first, then run live `POST /api/scan` against OWASP Juice Shop, record in `docs/justificativa2.txt`, commit, tag `sdd-084`, and push to `origin/main`.

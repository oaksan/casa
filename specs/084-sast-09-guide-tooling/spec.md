# SDD 084: Guide-Compliant Reference Tooling for SAST-09 (`semgrep` Multi-Language Unsafe Deserialization CWE-502)

## Control Reference
- **Control ID**: `SAST-09`
- **Guide Requirement**: Deserialization of untrusted data is avoided or integrity-protected (`Zero error-level findings of an untrusted-input deserialization sink without a type allowlist, ObjectInputFilter, or verified integrity check`).
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `semgrep`, `CodeQL`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Expand `CASA3-SAST-09-unsafe-deserialization*` Semgrep rules in `casa-assessment/rules/casa3_al1_sast.yml` across every Test Guide deserialization family:
   - **TS/JS**: `yaml.load` (excluding local `fs.readFileSync` static build specs and safe schema forms), `libxml` XXE (`XML_PARSE_NOENT`/`XML_PARSE_DTDLOAD`, `parseXmlString`, `XmlDocument.fromString`), `node-serialize` (`serialize.unserialize`), respecting preceding `timingSafeEqual` integrity verification;
   - **Python**: `pickle.load/loads`, `cPickle.loads`, `marshal.loads`, `jsonpickle.decode`, `yaml.unsafe_load`, `yaml.load` (excluding `SafeLoader`/`CSafeLoader` or `hmac.compare_digest`-guarded blobs);
   - **Java**: `ObjectInputStream.readObject()` without `setObjectInputFilter`, `XMLDecoder.readObject()`, SnakeYAML `new Yaml().load(...)` without `SafeConstructor`;
   - **PHP**: `unserialize($DATA)` without `['allowed_classes' => false]`;
   - **C#/.NET**: `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`, `LosFormatter`, and Newtonsoft `TypeNameHandling.{All,Auto,Objects,Arrays}`.
2. Add `evaluate_sast09_deserialization(repo)` in `casa-assessment/casa_audit/scanner.py` delegating to `_evaluate_semgrep_control_sarif(repo, "SAST-09")`, add `SAST-09` to `ERROR`-level gating in `run_sast_checks`, and expose `Semgrep AST 1.180.0 (Multi-Language CWE-502 Unsafe Deserialization Ruleset, SARIF 2.1.0)`.
3. Validate via `semgrep --validate`, add `test_iteration84_sast09_guide_tooling`, run full unittest suite first, then run live `POST /api/scan` on OWASP Juice Shop, document in `docs/justificativa2.txt`, commit, tag `sdd-084`, and push to GitHub.

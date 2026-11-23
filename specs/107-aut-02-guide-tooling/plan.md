# Implementation Plan 107 — AUT-02 (`SP 800-90B` + `200-Sample Harness`)

1. Add `estimate_sp800_90b_token_min_entropy(tokens)` and `evaluate_aut02_token_entropy(...)` in `casa-assessment/casa_audit/scanner.py` implementing NIST SP 800-90B §6.3.1 Most-Common-Value (99% upper confidence bound) across whole-token frequency and varying positional character columns, persisting `output/aut02-sp800-90b.json` and redacted `output/aut02-replayed.har`, and exporting `loginEndpoint` + `loginBody` for `AUT-03`/`05`/`06`.
2. Wire `results["AUT-02"]` inside `run_dynamic_and_protocol_checks`.
3. Add `test_iteration107_aut02_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering 200 distinct 128-bit CSPRNG tokens (`>= 64` bits -> `PASS` + redacted HAR verification), deterministic/colliding tokens (`FAIL`), and weak 32-bit random hex tokens (`< 64` bits -> `FAIL`).
4. Append `CONTROLE 37/61: AUT-02 (Iteração SDD 107)` to `docs/justificativa2.txt`.
5. Run full `unittest` suite (`40` tests) to completion, execute the live OWASP Juice Shop scan, commit, tag `sdd-107`, and push.

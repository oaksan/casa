# Implementation Plan 106 — AUT-01 (`SecLists` + Replay Harness)

1. Add curated SecLists default-credentials wordlist `casa-assessment/rules/seclists_aut01_default_creds.txt` and `SECLISTS_AUT01_CREDS` constant in `casa-assessment/casa_audit/scanner.py`.
2. Add `_load_seclists_default_credentials()` and `evaluate_aut01_default_credentials(...)` in `casa-assessment/casa_audit/scanner.py` merging SecLists generic defaults + product-derived vendor defaults (correlated from `CFG-03` version-disclosure findings and detected target metadata), probing active login surfaces with anti-SPA filtering, masking passwords, emitting a redacted HAR 1.2 harness capture (`output/aut01-replayed.har`), and exporting `jwtToken`/`activeLoginSurfaces`/`loginHeaders`/`loginStatus`.
3. Wire `results["AUT-01"]` inside `run_dynamic_and_protocol_checks`.
4. Add `test_iteration106_aut01_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering rejected corpus (`PASS` with redacted HAR), SecLists generic pair accepted (`FAIL` + `[REDACTED]` verification), and product-vendor default triggered from `CFG-03` disclosure (`FAIL`).
5. Append `CONTROLE 36/61: AUT-01 (Iteração SDD 106)` to `docs/justificativa2.txt`.
6. Run full `unittest` suite (`39` tests) to completion, execute the live OWASP Juice Shop scan, commit, tag `sdd-106`, and push.

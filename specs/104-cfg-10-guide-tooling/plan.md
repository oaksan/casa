# Implementation Plan 104 — CFG-10 (`OWASP ZAP` + `SecLists`)

1. Add curated SecLists administrative/operations wordlist `casa-assessment/rules/seclists_cfg10_admin.txt` and `SECLISTS_CFG10_WORDLIST` constant in `casa-assessment/casa_audit/scanner.py`.
2. Add `_lcs_line_similarity` and `evaluate_cfg10_admin_reachability(...)` in `casa-assessment/casa_audit/scanner.py` loading the SecLists wordlist, replaying authenticated routes unauthenticated, running differential authenticated vs unauthenticated comparisons (`LCS >= 0.90` with anti-SPA filter), and correlating OWASP ZAP `2.17.0` discovered URLs and alerts.
3. Wire `results["CFG-10"]` inside `run_dynamic_and_protocol_checks`.
4. Add `test_iteration104_cfg10_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering enforced auth (`401`/`403` unauth -> `PASS` via real ZAP `2.17.0`), exposed `/admin` & `/support/logs` (`LCS >= 0.90` -> `FAIL`), and unauthenticated replay of `/rest/wallet/balance` (`FAIL`).
5. Append `CONTROLE 34/61: CFG-10 (Iteração SDD 104)` to `docs/justificativa2.txt`.
6. Run the full `unittest` suite (`37` tests) to completion, execute the live OWASP Juice Shop scan, commit, tag `sdd-104`, and push.

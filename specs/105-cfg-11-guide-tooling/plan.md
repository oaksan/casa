# Implementation Plan 105 — CFG-11 (`dnsx` + `nuclei`)

1. Install official ProjectDiscovery `dnsx` (`v1.3.1`) under `/home/user/.local/bin/dnsx`.
2. Add curated Nuclei takeover fingerprint template `casa-assessment/rules/nuclei_cfg11/takeover-fingerprints.yaml`.
3. Add `DNSX_BIN` and `NUCLEI_CFG11_DIR` constants, `run_dnsx_resolve(...)`, and `evaluate_cfg11_dns_takeover(...)` in `casa-assessment/casa_audit/scanner.py` resolving host/CNAME chains via `dnsx` (`-cname -a -aaaa -json`), following up to 8 hops, running Nuclei (`rules/nuclei_cfg11`) for provider takeover banners, and matching all 16 cloud provider signatures.
4. Wire `results["CFG-11"]` inside `run_dynamic_and_protocol_checks`.
5. Add `test_iteration105_cfg11_guide_tooling` in `casa-assessment/tests/test_iteration1.py` covering live `dnsx` + `nuclei` against `localhost` (`PASS`), dangling CNAME to `.herokuapp.com` with `NXDOMAIN` (`FAIL`), and live HTTP GitHub Pages takeover banner caught by real Nuclei `v3.11.1` (`FAIL`).
6. Append `CONTROLE 35/61: CFG-11 (Iteração SDD 105)` to `docs/justificativa2.txt`.
7. Run full `unittest` suite (`38` tests) to completion, execute the live OWASP Juice Shop scan, commit, tag `sdd-105`, and push.

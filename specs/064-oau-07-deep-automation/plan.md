# Plan — SDD 064: OAU-07 Deep Automation

1. Reuse the `headless_storage_dump.js` snapshot (`aut08_snap`) directly in `OAU-07` to correlate live `localStorage`, `sessionStorage`, `IndexedDB`, and `document.cookie` exposures against observed tokens without redundant Chrome spawns.
2. Inspect `cfg06_aut06_findings` (`Set-Cookie` flags), live JS bundles (`main.js` backtick/quote calls), production Angular components (filtering `*.spec.ts`), and mobile preference stores.
3. Emit `CASA3-OAU-07` SARIF findings and validate empirically against OWASP Juice Shop (`http://localhost:3000`).
4. Document Control 56/61 in `docs/justificativa.txt`, assert in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-064`.

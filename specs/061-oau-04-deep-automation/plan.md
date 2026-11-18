# Plan — SDD 061: OAU-04 Deep Automation

1. Upgrade `OAU-04` in `casa-assessment/casa_audit/scanner.py` with active server authorization sampling (200 samples + SP 800-90B >= 128-bit estimator), callback state manipulation probes, and live bundle/source initiation + callback validation analysis.
2. Avoid noisy false positives on minified bundle `Math.random()` unless `state=` is actually constructed without Web Crypto CSPRNG, and inspect localized slice around `parseRedirectUrlParams` in `main.js` and `oauth.component.ts`.
3. Validate empirically against live OWASP Juice Shop (`http://localhost:3000`), document Control 53/61 in `docs/justificativa.txt`, assert in `tests/test_iteration1.py`, run `unittest`, and commit/tag `sdd-061`.

# Implementation Plan — Iteration 048 (`AUT-05`)

1. Replace the static `lib/insecurity.ts`-only `AUT-05` check in `casa-assessment/casa_audit/scanner.py` with a live authenticated logout + post-logout token/refresh replay harness.
2. Probe 6 logout endpoints (`POST`/`GET`) distinguishing genuine backend handlers from Angular SPA catch-all `200` shells.
3. Replay Bearer/Cookie tokens across 3 protected routes and expose `aut05_post_logout_accepted` / `aut05_replayed_token` for downstream `AUT-07` lifetime enforcement.
4. Emit `CASA3-AUT-05` results into `dast_sarif_results` (`output/dast-findings.sarif`).
5. Verify against OWASP Juice Shop (`http://localhost:3000`), update `docs/justificativa.txt` and `tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-048`, and push.

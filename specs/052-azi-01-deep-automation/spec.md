# SDD Iteration 052 Spec: AZI-01 Deep Automation

## Control Under Audit
- **ID:** `AZI-01`
- **Requirement:** Strong anti-CSRF mechanism on all state-changing authenticated functionality (`OWASP ASVS V4.2.2 (L1); CWE-352`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner relied strictly on static `"csurf" not in insec_txt` grep without executing dynamic CSRF replay requests or state-change re-reads.
2. Never tested the 3 required replay modes (anti-CSRF token removed, replaced, and taken from a second session) or `SameSite=None` cookie checks.
3. Missing `CASA3-AZI-01` SARIF 2.1.0 entries and redacted HAR 1.2 artifact pointers.

## Requirements
- Inspect `GET /profile` form for hidden anti-CSRF tokens (`_csrf`/`csrf_token`) and obtain a second valid session (`session_b_tok`).
- Execute `POST /profile` with cookie-only auth + `Origin: https://evil.example.com` across all 3 modes (removed, replaced, cross-session) and re-read `GET /profile` to confirm state mutation persistence.
- Check crawl `Set-Cookie` headers for `SameSite=None` and emit `CASA3-AZI-01` findings into `output/dast-findings.sarif`.

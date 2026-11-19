# Specification — SDD 069: WHK-03 Deep Automation (Control 61/61)

- **Control ID:** `WHK-03`
- **Title:** User-supplied callback URLs are SSRF-protected; signing secrets are not hardcoded or committed to version control
- **External References:** CASA v2.1.1 §7.3.1, §7.3.2; CWE-918
- **Applicable Profile:** `Web_Application`

## Requirements
1. Expand `discover_webhook_facilities` active POST discovery to inspect callback registration endpoints (`/api/webhooks/register`, `/webhooks/register`, `/api/callback`).
2. Start an ephemeral local SSRF callback listener (`ThreadingHTTPServer` supporting direct hits and `302` redirect chains) and replay 11 restricted URL vectors (`127.0.0.0/8`, `::1`, `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `169.254.169.254`, `fd00:ec2::254`, `fe80::/10`, redirect chain, DNS rebind `127.0.0.1.nip.io`).
3. Scan webhook handler/config sources for hardcoded `whsec_...` and `signing_secret` / `WEBHOOK_SECRET` string literals.
4. Emit `CASA3-WHK-03` findings to `output/dast-findings.sarif` alongside redacted HAR 1.2 and `tls-scan.json`.

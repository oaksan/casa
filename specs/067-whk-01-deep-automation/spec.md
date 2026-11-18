# Specification — SDD 067: WHK-01 Deep Automation

- **Control ID:** `WHK-01`
- **Title:** Webhook traffic is delivered exclusively over HTTPS with TLS 1.2+; cleartext endpoints are refused
- **External References:** CASA v2.1.1 §7.1.1; Standard Webhooks
- **Applicable Profile:** `Web_Application`

## Requirements
1. Discover inbound/outbound webhook receivers and handler configurations via workspace static inspection (`discover_webhook_facilities`) and active `POST` route probing (filtering SPA fallbacks and Express `500 Unexpected path:`).
2. Test cleartext `http://` webhook delivery (`FollowRedirects=False`), treating `3xx` redirects to `https://` as denied and `2xx` responses as failures (`WHK01_Cleartext_Delivery_Accepted`).
3. Verify receiver host TLS negotiation refuses TLS 1.0 / TLS 1.1 and supports TLS 1.2 / TLS 1.3.
4. Emit `CASA3-WHK-01` findings in `output/dast-findings.sarif` alongside `output/dast-capture.har` and `output/tls-scan.json`; return documented `Not_Covered` when zero webhook facilities exist (as in OWASP Juice Shop).

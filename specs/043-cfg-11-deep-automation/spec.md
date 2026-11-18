# SDD Iteration 043 Spec: CFG-11 Deep Automation

## Control Under Audit
- **ID:** `CFG-11`
- **Requirement:** No dangling DNS record on any declared host or its CNAME chain permits subdomain takeover (`OWASP ASVS V10.3.3 (L1); CWE-350`)
- **Surface:** `Web_Application`

## Gaps Identified
1. Scanner returned a static hardcoded `PASS` stub without resolving DNS (`CNAME`/`A`/`AAAA`), following CNAME chains, or checking cloud-provider takeover fingerprints.
2. Missing `CASA3-CFG-11` SARIF 2.1.0 integration and artifact links.

## Requirements
- Resolve `host` DNS records via `dig` (`CNAME`, `A`, `AAAA`) and `socket.getaddrinfo`, traversing up to 8 CNAME hops.
- Check CNAME chain hops, `NXDOMAIN` status, and HTTP response bodies against 16 cloud-provider takeover fingerprints (GitHub Pages, Heroku, S3, Azure, Netlify, Vercel, CloudFront, Fastly, Shopify, Pantheon, ReadTheDocs, Surge.sh).
- Emit `CASA3-CFG-11` results to `output/dast-findings.sarif` alongside `output/dast-capture.har`.

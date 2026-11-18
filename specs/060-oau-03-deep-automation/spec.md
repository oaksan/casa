# Specification — SDD 060: OAU-03 Deep Automation

- **Control ID:** `OAU-03`
- **Title:** The application registers only exact, non-wildcard redirect URIs, and its own callback endpoint contains no open redirect or forwarding chain
- **External References:** RFC 9700 §2.1; CWE-601
- **Applicable Profile:** `All`

## Requirements
1. Extract registered/observed OAuth `redirect_uri` values from live application configuration (`/rest/admin/application-configuration`), redacted HAR traffic, client JS bundles/sources, and `config/default.yml`.
2. Flag wildcard redirect URIs (`*`) and cleartext `http:` URIs outside loopback addresses (`localhost`, `127.0.0.1`, `::1`).
3. Fuzz OAuth callback and redirector endpoints across `redirect`, `next`, `continue`, `return_to`, `RelayState` (plus `to` forwarding allowlist bypasses) inspecting `3xx Location`, `<meta http-equiv="refresh">`, and script redirects for off-allowlist host resolution.
4. Emit findings with ruleId `CASA3-OAU-03` to `output/dast-findings.sarif` (SARIF 2.1.0) and record HTTP probes in `output/dast-capture.har` (redacted HAR 1.2).

# SDD 166 — CFG-11 Reavaliação Neon (Subdomain & DNS Takeover Prevention)

## Controle Alvo
- **ID:** `CFG-11` (Controle `35/61`, Domínio 4 — Server Configuration & Response Headers; **Encerramento do Domínio 4**)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 764–780)
- **Ferramentas de Referência do Guia:** `dnsx, Nuclei (takeovers/ templates), can-i-take-over-xyz`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza ProjectDiscovery `dnsx` 1.3.1 + `Nuclei` 3.11.1 (`rules/nuclei_cfg11`) + catálogo `can-i-take-over-xyz`. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Cobertura de provedores `can-i-take-over-xyz`:** `takeover_fingerprints` cobria 16 sufixos de nuvem, omitindo provedores comuns listados em `can-i-take-over-xyz` (`.fly.dev`, `.bitbucket.io`, `.ghost.io`, `.zendesk.com`, `.unbouncepages.com`, `.wpengine.com`, `.azureedge.net`, `.azure-api.net`).
3. **Lacuna 2 — Múltiplos subdomínios em escopo (`extra_hosts`):** O Passo 1 do Guia exige resolver cadeias CNAME *"For every declared hostname and subdomain in scope"*, mas `evaluate_cfg11_dns_takeover` avaliava apenas o hostname primário de `target_url`.

## Critérios de Aceitação
- `takeover_fingerprints` cobre 24 provedores cloud `can-i-take-over-xyz`.
- `evaluate_cfg11_dns_takeover` aceita `extra_hosts: list[str] | None = None` e resolve/verifica cadeias CNAME dangling em todos os subdomínios declarados.
- Encerramento do Domínio 4 validado com suíte completa `unittest discover` (99/99 `OK`) + scan live completo no OWASP Juice Shop.

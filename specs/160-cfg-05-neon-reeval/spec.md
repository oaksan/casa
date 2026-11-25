# SDD 160 — CFG-05 Reavaliação Neon (Clickjacking Protection)

## Controle Alvo
- **ID:** `CFG-05` (Controle `29/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 639–658)
- **Ferramentas de Referência do Guia:** `OWASP ZAP (rule 10020 Anti-clickjacking Header), curl`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza OWASP ZAP 2.17.0 (Regra Passiva `10020`) + inspetor multi-rota de `X-Frame-Options` e CSP `frame-ancestors`. Zero uso de Burp Suite pago.
2. **Bug de Segurança Identificado em `_has_valid_frame_ancestors`:** A regex anterior `^(?:https?://)?[a-z0-9.*:-]+$` aceitava indevidamente wildcards de esquema (`frame-ancestors https:`, `frame-ancestors http:`, `frame-ancestors data:`) e wildcards genéricos (`frame-ancestors https://*`, `frame-ancestors *.*`), que permitem que qualquer origem externa enquadre a aplicação em iframe, violando o critério do Guia (`'none'`, `'self'`, ou origens explícitas).

## Critérios de Aceitação
- `_has_valid_frame_ancestors` rejeita `https:`, `http:`, `data:`, `*`, `https://*`, `*.*` e `*.com`.
- `_has_valid_frame_ancestors` aceita `'none'`, `'self'`, origens explícitas (`https://partner.example.com`, `https://*.trusted.example.com:8443`, `partner.example.com`) e `localhost`.
- Regressão (`test_iteration99_cfg05_guide_tooling`) e novo teste (`test_iteration160_cfg05_neon_reeval`) passam 100%.

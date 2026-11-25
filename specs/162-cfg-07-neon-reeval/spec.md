# SDD 162 — CFG-07 Reavaliação Neon (Anti-Caching Headers on Sensitive Responses)

## Controle Alvo
- **ID:** `CFG-07` (Controle `31/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 681–700)
- **Ferramentas de Referência do Guia:** `OWASP ZAP (rules 10049 Storable and Cacheable Content, 10015 Re-examine Cache-Control Directives)`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza OWASP ZAP 2.17.0 (`10049`/`10015`) + inspetor autenticado de `Cache-Control: no-store`. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Acoplamento a rotas fixas de login/alvo:** `evaluate_cfg07_anti_caching` não aceitava `auth_headers` nem `endpoints` externos, dependendo exclusivamente do fluxo `/api/Users/` + `/rest/user/login` e de uma lista fixa de rotas.
3. **Lacuna 2 — Diretiva contraditória `public, no-store`:** `Cache-Control: public, no-store` era aceito como válido, apesar de `public` autorizar armazenamento em caches compartilhados (violando o objetivo de anti-caching em respostas sensíveis).

## Critérios de Aceitação
- `evaluate_cfg07_anti_caching` aceita `auth_headers: dict[str, str] | None = None` e `endpoints: list[str] | None = None`.
- `Cache-Control: public, no-store` é rejeitado como violação de anti-caching.
- `Cache-Control: no-store, private` em endpoints customizados autenticados passa (`PASS`).
- Regressão (`test_iteration101_cfg07_guide_tooling`) e novo teste (`test_iteration162_cfg07_neon_reeval`) passam 100%.

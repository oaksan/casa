# SDD 163 — CFG-08 Reavaliação Neon (CORS Policy Restrictive)

## Controle Alvo
- **ID:** `CFG-08` (Controle `32/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 702–721)
- **Ferramentas de Referência do Guia:** `OWASP ZAP (rule 10098 Cross-Domain Misconfiguration), curl`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza OWASP ZAP 2.17.0 (Regra Passiva `10098`) + sonda ativa multi-origem CORS. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Bypass por prefixo (`startsWith`):** A sonda ativa testava origem estrangeira (`https://evil.example.com`), `null` e sufixo (`https://not<host>`), mas não testava bypass de validação por prefixo (`https://<host>.evil.example.com`), falha clássica em allowlists CORS baseadas em `startsWith` ou regex não ancorada.
3. **Lacuna 2 — Endpoints configuráveis:** `evaluate_cfg08_cors` não aceitava parâmetro `endpoints` para testar rotas arbitrárias de outras aplicações.

## Critérios de Aceitação
- `evaluate_cfg08_cors` envia também `Origin: https://<host>.evil.example.com` (`prefix_matching_origin`) e registra `reflected_prefix_matching_origin` quando refletida.
- Aceita parâmetro opcional `endpoints` mantendo total retrocompatibilidade.
- Regressão (`test_iteration102_cfg08_guide_tooling`) e novo teste (`test_iteration163_cfg08_neon_reeval`) passam 100%.

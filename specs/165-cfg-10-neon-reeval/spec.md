# SDD 165 — CFG-10 Reavaliação Neon (Administrative Interfaces Not Publicly Reachable)

## Controle Alvo
- **ID:** `CFG-10` (Controle `34/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 743–762)
- **Ferramentas de Referência do Guia:** `OWASP ZAP, ffuf + SecLists/Discovery/Web-Content/common.txt`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza OWASP ZAP 2.17.0 + SecLists Admin Wordlist + análise diferencial autenticado/não-autenticado (similaridade LCS >= 0.90). Zero uso de Burp Suite pago.
2. **Lacuna 1 — Rotas e wordlist fixas:** `evaluate_cfg10_admin_reachability` não aceitava parâmetros opcionais `auth_routes` e `admin_wordlist` para avaliar rotas específicas de aplicações arbitrárias.
3. **Lacuna 2 — Falsos negativos por campos voláteis (timestamps/UUIDs) ou ausência de `auth_headers`:**
   - Respostas JSON com timestamps ISO-8601 ou UUIDs por requisição podiam reduzir a similaridade LCS linha-a-linha abaixo de 0.90 mesmo quando o conteúdo protegido era idêntico.
   - Em modo sem `auth_headers`, um painel administrativo que respondesse `200 OK` com conteúdo administrativo real (sem SPA fallback nem formulário de login) tinha `sim_adm = 0.0` e passava despercebido.

## Critérios de Aceitação
- `evaluate_cfg10_admin_reachability` aceita `auth_routes` e `admin_wordlist` opcionais.
- Normalização de timestamps ISO-8601/UUIDs evita falsos negativos na comparação LCS >= 0.90.
- Quando `auth_headers` não é fornecido, painel admin `200 OK` sem formulário de login e sem SPA fallback é detectado como `exposed_admin_wordlist_path`.
- Regressão (`test_iteration104_cfg10_guide_tooling`) e novo teste (`test_iteration165_cfg10_neon_reeval`) passam 100%.

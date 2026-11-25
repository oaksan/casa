# SDD 172 — AUT-06 Reavaliação Neon (Session Cookie Flags: Secure, HttpOnly, SameSite)

## Controle Alvo
- **ID:** `AUT-06` (Controle `41/61`, Domínio 5 — Authentication & Session Management)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 898–916)
- **Ferramentas de Referência do Guia:** `ZAP, Burp Suite`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita — SEM Burp Suite pago):** Utiliza OWASP ZAP 2.17.0 (`10010`, `10011`, `10054`) + inspetor `Set-Cookie` com HAR 1.2 redigido e SARIF 2.1.0. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Identificação comportamental de cookies de sessão (Guia L909):** O Guia define cookies de sessão como *"those whose removal ends the authenticated session"*. Anteriormente, `evaluate_aut06_session_cookie_flags` identificava cookies de sessão apenas por heurística de nome (`_is_session_cookie_name`), deixando passar cookies de sessão com nomes arbitrários (ex.: `app_c`, `x_state`).
3. **Lacuna 2 — Deleção de cookie (`Max-Age=0` / valor vazio):** Cabeçalhos `Set-Cookie` emitidos apenas para apagar um cookie (`Max-Age=0` ou valor vazio) não devem ser confundidos com emissão de cookie de sessão ativo.

## Critérios de Aceitação
- `evaluate_aut06_session_cookie_flags` aceita `protected_endpoint` e `session_cookie_names` opcionais e executa ablação comportamental (remoção 1-a-1 de cookies) para identificar cookies de sessão de nomes arbitrários.
- Cookies de sessão de nome arbitrário (ex.: `app_c`) sem `Secure`/`HttpOnly`/`SameSite=Lax|Strict` falham `AUT-06`.
- `SameSite=None` é rejeitado; deleções explícitas (`Max-Age=0`, valor vazio) são ignoradas.
- Regressão (`test_iteration111_aut06_guide_tooling`) e novo teste (`test_iteration172_aut06_neon_reeval`) passam 100%.

# SDD 169 — AUT-03 Reavaliação Neon (Session Fixation Prevented)

## Controle Alvo
- **ID:** `AUT-03` (Controle `38/61`, Domínio 5 — Authentication & Session Management)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 835–853)
- **Ferramentas de Referência do Guia:** `scripted harness`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza harness Python de captura pré-autenticação, login com fixação e replay pós-login com HAR 1.2 redigido e SARIF 2.1.0. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Logins com redirecionamento `302`/`303` + `Set-Cookie`:** `evaluate_aut03_session_fixation` só extraía o novo identificador de sessão quando `200 <= post_st3 < 300`, gerando falso FAIL em aplicações server-side que rotacionam o cookie de sessão em um redirect `302 Found` após o login.
3. **Lacuna 2 — Nomes de cookie de fixação PHP / ASP.NET:** `fixation_cookie_pairs` testava `token`, `connect.sid` e `JSESSIONID`, omitindo `PHPSESSID` e `ASP.NET_SessionId`.

## Critérios de Aceitação
- `evaluate_aut03_session_fixation` extrai `Set-Cookie` de sessão também em respostas `302`/`303` do login.
- `fixation_cookie_pairs` e o replay pós-login incluem `PHPSESSID` e `ASP.NET_SessionId`.
- Regressão (`test_iteration108_aut03_guide_tooling`) e novo teste (`test_iteration169_aut03_neon_reeval`) passam 100%.

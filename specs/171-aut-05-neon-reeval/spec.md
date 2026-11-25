# SDD 171 — AUT-05 Reavaliação Neon (Logout Invalidates Session & Refresh Tokens)

## Controle Alvo
- **ID:** `AUT-05` (Controle `40/61`, Domínio 5 — Authentication & Session Management)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 877–895)
- **Ferramentas de Referência do Guia:** `scripted harness`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza harness Python de logout ativo + replay de cookie/token de sessão e refresh token com HAR 1.2 redigido e SARIF 2.1.0. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Rotas REST de logout (`POST /logout`, `DELETE /api/session`):** `logout_endpoints` padrão não incluía `POST /logout` nem `DELETE /api/session`.
3. **Lacuna 2 — Semântica `Denied` (Guia L25) em respostas JSON 200:** Um endpoint que retorna `200 OK` com `{"authenticated": false}` ou `{"error": "Unauthorized"}` após logout podia gerar falso FAIL.
4. **Lacuna 3 — Replay de refresh token RFC 6749 `application/x-www-form-urlencoded`:** Endpoints `/oauth/token` compatíveis com RFC 6749 §6 exigem `grant_type=refresh_token&refresh_token=...` em form-urlencoded; o harness só enviava JSON.

## Critérios de Aceitação
- `logout_endpoints` padrão inclui `POST /logout` e `DELETE /api/session`.
- Resposta `200 OK` com payload JSON explícito de negação (`{"authenticated": false}`, `{"error": "Unauthorized"}`) é classificada como `Denied` (L25).
- Refresh token sobrevivente em endpoint RFC 6749 `application/x-www-form-urlencoded` (`/oauth/token`) é detectado e falha `AUT-05`.
- Regressão (`test_iteration110_aut05_guide_tooling`) e novo teste (`test_iteration171_aut05_neon_reeval`) passam 100%.

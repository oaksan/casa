# SDD 170 — AUT-04 Reavaliação Neon (No Tokens/Credentials in URLs or Referer)

## Controle Alvo
- **ID:** `AUT-04` (Controle `39/61`, Domínio 5 — Authentication & Session Management)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 856–874)
- **Ferramentas de Referência do Guia:** `ZAP, Burp Suite`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita — SEM Burp Suite pago):** Utiliza OWASP ZAP 2.17.0 (`3`, `10024`, `10025`) + inspetor HAR 1.2 redigido (URL, query, fragmento, `Referer`, `Location`) + sonda ativa CWE-598. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Tokens URL-encoded (`%2B`, `%2F`, `%2E`):** A busca de `observed_tokens` e `jwt_url_re` em URLs, `Referer` e `Location` operava apenas sobre a string bruta, podendo perder tokens percent-encoded.
3. **Lacuna 2 — Parâmetros sensíveis adicionais:** `sens_param_re` e `_redact_url_str` não cobriam `api_key`, `apikey`, `auth_token`, `bearer`, `client_secret`, `code_verifier` e `secret`.

## Critérios de Aceitação
- Tokens URL-encoded em URLs, `Referer` e `Location` são detectados e redigidos no HAR 1.2.
- `api_key`/`client_secret`/`code_verifier`/`auth_token` em query strings ou fragmentos falham `AUT-04`.
- Regressão (`test_iteration109_aut04_guide_tooling`) e novo teste (`test_iteration170_aut04_neon_reeval`) passam 100%.

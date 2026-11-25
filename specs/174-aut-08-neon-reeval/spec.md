# SDD 174 — AUT-08 Reavaliação Neon (Client-Side Storage Clean & Cleared on Logout)

## Controle Alvo
- **ID:** `AUT-08` (Controle `43/61`, Domínio 5 — Authentication & Session Management; **Encerramento do Domínio 5**)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 940–958)
- **Ferramentas de Referência do Guia:** `Playwright` (referência; Google Chrome Headless via CDP em Node.js produz dump + SARIF 2.1.0 + HAR 1.2 redigido conforme L21)

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza Google Chrome Headless via CDP (`scripts/headless_storage_dump.js`) + inspetor de `localStorage`, `sessionStorage`, `IndexedDB` e cookies não-`HttpOnly` antes e depois do logout. Zero uso de Burp Suite pago.
2. **Lacuna 1 — PANs formatados com hífen/espaço:** `pan_re8 = r"\b\d{13,19}\b"` não detectava números de cartão válidos segundo Luhn armazenados com hífens ou espaços (ex.: `4532-0151-1283-0366`).
3. **Lacuna 2 — Segredos aninhados em JSON sob chave benigna:** Objetos JSON serializados sob chaves como `localStorage['app_state']` contendo `refresh_token`/`access_token`/`password` opacos (não-JWT) não eram sinalizados quando o token opaco não estava em `observed_tokens`.
4. **Lacuna 3 — Correspondência case-insensitive de valores de perfil IdP:** Valores de e-mail/perfil do IdP normalizados em minúsculas no storage podiam não casar com `idp_profile_values` capitalizados.

## Critérios de Aceitação
- `_scan_storage_snapshot` detecta PANs formatados (`-` ou espaço) válidos segundo Luhn, chaves de auth aninhadas em JSON serializado sob chaves benignas, e valores de perfil IdP case-insensitive.
- Encerramento do Domínio 5 validado com suíte completa `unittest discover` (107/107 `OK`) + scan live completo no OWASP Juice Shop.

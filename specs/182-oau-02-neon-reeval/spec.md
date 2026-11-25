# SDD 182 — Reavaliação Neon do Controle 51/61: OAU-02

## Objetivo
Reavaliar o controle `OAU-02` (PKCE with `S256` Enforced on All Authorization Code Flows — RFC 7636; RFC 9700 §2.1.1; MASA 1.3.1.1/2.3.1.1) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1117–L1135):
1. Confirmar uso exclusivo de ferramentas gratuitas (proxy interceptador HTTP local + prova criptográfica SHA-256 + `semgrep` `CASA3-OAU-02`, sem Burp Suite pago).
2. Validar limites RFC 7636 §4.1–§4.2 completos para `code_challenge` (43..128 caracteres base64url sem padding) e `code_verifier` (43..128 caracteres unreserved `[A-Za-z0-9\-._~]`) nas trocas de token capturadas.

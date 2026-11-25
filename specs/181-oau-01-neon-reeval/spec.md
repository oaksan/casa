# SDD 181 — Reavaliação Neon do Controle 50/61: OAU-01

## Objetivo
Reavaliar o controle `OAU-01` (Only Authorization Code Flow; Implicit and ROPC Prohibited — RFC 9700 §2.1.2, §2.4; RFC 6749) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1096–L1114):
1. Confirmar uso exclusivo de ferramentas gratuitas (proxy interceptador HTTP local + `semgrep` `CASA3-OAU-01`, sem Burp Suite pago).
2. Corrigir regex de `response_type=` em `evaluate_oau01_grant_type` que truncava fluxos híbridos separados por espaço (`response_type=code id_token`), e detectar literais de objeto/JSON `responseType` / `response_type` e `grantType: "password"`.

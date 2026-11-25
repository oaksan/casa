# SDD 188 — Reavaliação Neon do Controle 57/61: OAU-08

## Objetivo
Reavaliar o controle `OAU-08` (Access Tokens Transmitted Only in `Authorization` Header `Bearer`/`DPoP` — RFC 6750 §2.3; ASVS V3.1.1) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1243–L1261):
1. Confirmar uso exclusivo de ferramentas gratuitas (proxy interceptador HTTP local + auditoria HAR 1.2 + probes de query-token + `semgrep` `CASA3-OAU-08`, sem Burp Suite pago).
2. Ampliar a auditoria de HAR em `evaluate_oau08_token_transport` para detectar `access_token=`/`id_token=` opacos em fragmentos de URL (`#access_token=...`) e em corpos form-encoded (`request.postData.text`) de endpoints de recurso, além de redigir `postData.text` no HAR salvo.

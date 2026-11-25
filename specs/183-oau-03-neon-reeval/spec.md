# SDD 183 — Reavaliação Neon do Controle 52/61: OAU-03

## Objetivo
Reavaliar o controle `OAU-03` (Exact, Non-Wildcard Redirect URIs & No Callback Open Redirect — RFC 9700 §2.1; CWE-601) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1138–L1156):
1. Confirmar uso exclusivo de ferramentas gratuitas (proxy interceptador HTTP local + fuzzer de callback NoRedirect gerando HAR 1.2 redigido e SARIF 2.1.0, sem Burp Suite pago).
2. Enforçar a regra de superfície do Guia (L1154–L1155): redirecionamentos `http:` em loopback (`localhost`/`127.0.0.1`/`[::1]`) só são isentos em superfícies `Mobile` ou `Native`; e atualizar `_inspect_cb` para usar `_parse_redirect_scheme_host` (normalizando `/\` e detectando `javascript:`/`data:`).

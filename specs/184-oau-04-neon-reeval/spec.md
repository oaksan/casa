# SDD 184 — Reavaliação Neon do Controle 53/61: OAU-04

## Objetivo
Reavaliar o controle `OAU-04` (`state` and OIDC `nonce` CSPRNG-Generated, Bound to Session & Validated on Return — RFC 9700 §4.7; OIDC Core §3.1.2.1; CWE-352) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1159–L1177):
1. Confirmar uso exclusivo de ferramentas gratuitas (proxy interceptador HTTP local + estimador NIST SP 800-90B + harness de replay de `state`/`nonce` + `semgrep`, sem Burp Suite pago).
2. Descontar colunas constantes (prefixos/sufixos fixos) no cálculo de min-entropia de `state`, ampliar detecção de emissão de sessão no callback para qualquer cookie de sessão (`_is_session_cookie_name` sem `Max-Age=0`) e adicionar `run_semgrep: bool = True`.

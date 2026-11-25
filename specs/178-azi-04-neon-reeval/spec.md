# SDD 178 — Reavaliação Neon do Controle 47/61: AZI-04

## Objetivo
Reavaliar o controle `AZI-04` (No OS Command Injection — ASVS V5.3.8, CWE-78) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1035–L1047):
1. Auditar ferramentas gratuitas (OWASP ZAP regra `90020` + listener OOB HTTP e UDP DNS local sem Burp Suite pago).
2. Endurecer `_parse_dns_qname` contra ponteiros de compressão DNS (`0xC0`), adicionar parâmetro `oob_wait_sec` e reconhecer marcadores Windows `nt authority\system|local service|network service` na resposta.

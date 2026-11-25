# SDD 190 — Reavaliação Neon do Controle 59/61: WHK-01

## Objetivo
Reavaliar o controle `WHK-01` (Webhook Traffic Over HTTPS with TLS 1.2+; Cleartext Refused — CASA v2.1.1 §7.1.1; Standard Webhooks) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1290–L1308):
1. Confirmar uso exclusivo de ferramentas gratuitas (`testssl.sh` + harness de entrega cleartext/TLS + `semgrep` `CASA3-WHK-01` gerando HAR 1.2 redigido, JSON `testssl.sh` e SARIF 2.1.0; sem ferramentas pagas).
2. Normalizar a correspondência de protocolos do `testssl.sh` (`SSLv2`, `SSLv3`, `TLS1`/`TLSv1`/`TLS 1.0`..`TLS 1.3`), incluir `SSLv2`/`SSLv3` na detecção de TLS legado em `evaluate_whk01_delivery_tls` e validar que redirecionamentos 3xx HTTPS possuam hostname válido.

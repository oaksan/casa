# SDD 191 — Reavaliação Neon do Controle 60/61: WHK-02

## Objetivo
Reavaliar o controle `WHK-02` (Payloads Authenticated with HMAC-SHA256+ & Timing-Safe Comparison — CASA v2.1.1 §7.2.1, §7.2.2; CWE-208) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1311–L1329):
1. Confirmar uso exclusivo de ferramentas gratuitas (harness de entrega assinada com 4 vetores inválidos + `semgrep` `CASA3-WHK-02`, gerando HAR 1.2 redigido e SARIF 2.1.0; sem ferramentas pagas).
2. Incluir cabeçalhos **Standard Webhooks** (`webhook-id`, `webhook-timestamp`, `webhook-signature: v1,<b64>`) nos 3 vetores assinados, expandir APIs constant-time (`hash_equals`, `secure_compare`, `FixedTimeEquals`) em `scanner.py` e `casa3_al1_oauth.yml`, e aplicar guarda `_is_json_denial` (Guia L25) em respostas HTTP 2xx.

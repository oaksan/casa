# SDD 187 — Reavaliação Neon do Controle 56/61: OAU-07

## Objetivo
Reavaliar o controle `OAU-07` (Access & Refresh Tokens Held Only in Platform Secure Storage / `HttpOnly; Secure` Cookie — MASA 1.1.1.1/2.1.1.1; CWE-922; ASVS V6.4.1) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1222–L1240):
1. Confirmar uso exclusivo de ferramentas gratuitas (dump de storage via Chrome Headless CDP + auditor de `Set-Cookie` + inspetor MobSF-style APK/IPA/XML/plist + `semgrep` `CASA3-OAU-07`, sem ferramentas pagas).
2. Corrigir análise de múltiplos `Set-Cookie` concatenados em `evaluate_oau07_token_storage` usando `_split_set_cookie_headers` (filtrando deleções `Max-Age=0`) e inspecionar valores JWT/`observed_token` dentro de bancos IndexedDB mesmo com nomes benignos.

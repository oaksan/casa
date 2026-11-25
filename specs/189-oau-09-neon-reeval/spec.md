# SDD 189 — Reavaliação Neon do Controle 58/61: OAU-09 (Fechamento do Domínio 7)

## Objetivo
Reavaliar o controle `OAU-09` (Backend IdP Token Validation: Signature, `iss`, `aud`, `exp`, `scope`, `alg:none` & Algorithm Confusion — RFC 9700 §4.9; RFC 8725; CWE-347) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1264–L1284) e concluir o Domínio 7 (`OAU-01`..`OAU-09`):
1. Confirmar uso exclusivo de ferramentas gratuitas (harness de replay multi-vetor equivalente a `jwt_tool` + `semgrep` `CASA3-OAU-09`, gerando HAR 1.2 redigido e SARIF 2.1.0; sem ferramentas pagas).
2. Expandir `oau09_vectors` de 7 para 9 vetores (`unsigned_alg_none_mixedcase` e `nbf_future_claim`) e aplicar semântica `Denied` do Guia (L25) via `not _is_json_denial(v9_body)` em respostas HTTP 2xx.
3. Fechar o Domínio 7 com suíte completa `unittest discover` (122 testes) + scan ao vivo completo no OWASP Juice Shop.

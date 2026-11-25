# SDD 186 — Reavaliação Neon do Controle 55/61: OAU-06

## Objetivo
Reavaliar o controle `OAU-06` (No Client Secret Embedded in Public Client Binary, Bundle or Extension Package — RFC 8252 §8.5; CWE-798) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1201–L1219):
1. Confirmar uso exclusivo de ferramentas gratuitas (extração de strings/constantes de arquivos/binários `.apk`/`.ipa`/`.asar`/`.crx`/`.xpi` + prova ativa em token endpoint + `semgrep` `CASA3-OAU-06`, sem ferramentas pagas).
2. Completar a auditoria de HAR 1.2 em `evaluate_oau06_client_secret_scanner` para inspecionar `request.postData.text` (`client_secret=` / `"client_secret"`) e credenciais `Authorization: Basic` em requisições `/token` de clientes públicos.

# SDD 179 — Reavaliação Neon do Controle 48/61: AZI-05

## Objetivo
Reavaliar o controle `AZI-05` (No Local/Remote File Inclusion or Path Traversal — ASVS V5.3.9, V12.3.2, V12.3.3; CWE-22, CWE-98) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1050–L1068):
1. Confirmar uso exclusivo de ferramentas gratuitas (OWASP ZAP regras `6`/`7` + matriz de path traversal e listener RFI OOB local, sem Burp Suite pago).
2. Expandir `lfi_marker_re` (Windows `win.ini` e `/etc/hosts`), adicionar forma Windows backslash em `param_targets`, isolar atribuição de callbacks RFI por endpoint (`hits_before`) para eliminar falsos positivos entre múltiplos `rfi_targets`, e expor `run_rfi`.

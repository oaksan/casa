# SDD 180 — Reavaliação Neon do Controle 49/61: AZI-06 (Fechamento do Domínio 6)

## Objetivo
Reavaliar o controle `AZI-06` (No Open Redirect or Unvalidated Forward; HTTP Parameter Pollution Handled Safely — ASVS V5.1.5, V5.1.1; CWE-601, CWE-235) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1071–L1089) e concluir o Domínio 6 (`AZI-01`..`AZI-06`):
1. Confirmar uso exclusivo de ferramentas gratuitas (OWASP ZAP regras `20019`/`20014` + verificador NoRedirect e HPP diferencial, sem Burp Suite pago).
2. Corrigir normalização de redirecionamentos com barras invertidas (`/\host`, `\\host`), detectar pseudo-esquemas inseguros (`javascript:`, `data:`) e suportar `url='...'` com aspas em `<meta http-equiv="refresh">`.
3. Fechar o Domínio 6 executando a suíte completa `unittest discover` e um scan ao vivo completo contra OWASP Juice Shop.

# SDD 193 — Indicador de Progresso em Tempo Real do Scan Automatizado AL1

## Problema
Ao clicar no botão **"▶ Executar Scan Automatizado AL1"** em `casa-assessment/frontend/assess.html`, a interface exibia apenas o texto estático `"Executando verificações automatizadas do AL1 (SCA, SAST, TLS, CFG, AUT, AZI, OAU, WHK)..."` até o término integral da requisição síncrona `POST /api/scan` (que pode levar vários minutos ao executar Semgrep, testssl.sh, OWASP ZAP, sqlmap e Chrome Headless).

## Objetivo
Implementar acompanhamento em tempo real do andamento do scan AL1 (61 controles / 8 domínios):
1. **Engine (`scanner.py`):** adicionar callback opcional `progress_cb` em `run_automated_al1_scan`, `run_sca_checks`, `run_sast_checks` e `run_dynamic_and_protocol_checks`, emitindo eventos ao iniciar cada domínio (`SCA`, `SAST`, `TLS`, `CFG`, `AUT`, `AZI`, `OAU`, `WHK`, `FINAL`) e imediatamente à conclusão de cada controle individual (`0/61` → `61/61`).
2. **Servidor (`server.py`):** manter `POST /api/scan` 100% compatível e adicionar endpoints assíncronos `POST /api/scan/start` (HTTP 202 com `scan_id`) e `GET /api/scan/status?id=<scan_id>` (HTTP 200 com `status`, `progress`, contadores por domínio, contadores por veredito, tempo decorrido e `results` ao concluir).
3. **Frontend (`assess.html`, `styles.css`, `app.js`):** exibir painel de progresso em tempo real com barra animada (`0%–100%`), contador `N/61`, cronômetro decorrido (`MM:SS`), etapa/domínio atual, 8 chips de domínio (`SCA`..`WHK`) com progresso individual, contadores ao vivo (`PASS`/`FAIL`/`N/A`/`N/C`), último controle concluído e suporte completo a i18n (`PT`/`EN`), mantendo fallback automático para `POST /api/scan`.

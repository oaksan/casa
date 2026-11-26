# Tarefas — SDD 193 (Progresso em Tempo Real do Scan AL1)

- [x] Criar especificação, plano e tarefas em `specs/193-scan-progress-ui/`
- [x] Adicionar `_ProgressDict` e `progress_cb` em `casa-assessment/casa_audit/scanner.py`
- [x] Implementar `POST /api/scan/start` e `GET /api/scan/status` em `casa-assessment/casa_audit/server.py`
- [x] Implementar painel visual de progresso em tempo real e polling em `assess.html`, `styles.css` e `app.js`
- [x] Criar `test_iteration193_scan_progress_api_and_ui`, validar regressão, reiniciar servidor na porta 8080, commitar e publicar `sdd-193`

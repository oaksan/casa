# Plano — SDD 193 (Progresso em Tempo Real do Scan AL1)

1. **`casa-assessment/casa_audit/scanner.py`:**
   - Criar `_ProgressDict(dict)` e helper `_emit_progress(...)`.
   - Adicionar parâmetro opcional `progress_cb=None` em `run_sca_checks`, `run_sast_checks`, `run_dynamic_and_protocol_checks` e `run_automated_al1_scan`.
   - Emitir eventos de fase (`SCA`..`WHK` + `FINAL`) e eventos de controle sempre que `results[cid]` for gravado.
2. **`casa-assessment/casa_audit/server.py`:**
   - Implementar registro thread-safe `_SCAN_JOBS` com execução em background (`threading.Thread`), `POST /api/scan/start` (HTTP 202) e `GET /api/scan/status?id=<scan_id>` (HTTP 200).
   - Preservar `POST /api/scan` síncrono intacto.
3. **`casa-assessment/frontend/{assess.html,styles.css,app.js}`:**
   - Adicionar `#scan-progress-panel` dentro de `.automation-panel` com barra de progresso animada, etapa atual, `N/61` + `%` + cronômetro, 8 chips de domínio, resumo de vereditos e último controle avaliado.
   - Atualizar clique de `#btn-run-auto` para iniciar via `POST /api/scan/start`, fazer polling em `GET /api/scan/status?id=...` a cada 600ms e aplicar resultados ao concluir.
4. **Validação:**
   - Adicionar `test_iteration193_scan_progress_api_and_ui` em `casa-assessment/tests/test_neon_reeval.py` + rodar regressão `test_http_server_and_api_scan_endpoint`.
   - Reiniciar daemon `casa_audit` na porta `8080`, verificar endpoints ao vivo, documentar em `docs/justificativaNeon.txt`, commitar, criar tag `sdd-193` e fazer push.

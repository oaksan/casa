# Plano — SDD 195 (Evolução Pass Rate & Seletor de Histórico de Relatórios)

1. **`casa-assessment/casa_audit/server.py`:**
   - Adicionar `HISTORY_STORE_PATH`, helpers `_load_scan_history_store`, `get_app_scan_history`, `append_app_scan_history`, `clear_app_scan_history`.
   - Expor rotas `GET/POST/DELETE /api/applications/history` e limpar histórico ao deletar uma aplicação.
2. **`casa-assessment/frontend/{assess.html,styles.css,app.js}`:**
   - Atualizar `?v=sdd195` em `assess.html`.
   - Adicionar estilos da barra seletora de execuções (`.report-history-bar`), banner de visualização histórica (`.history-banner`) e gráfico SVG de evolução (`.evolution-card`, `.evo-svg`, pontos interativos, delta badge).
   - Em `app.js`:
     - Gerenciar `appScanHistory` (por `activeAppId`) com sincronização em `/api/applications/history` + `localStorage`, além de seed automático caso exista um scan prévio sem histórico.
     - Gravar snapshot completo em `applyScanResults(...)` com resumo (`passRate`, `passedCount`, `applicableCount`, `failCount`, etc.) e cópia imutável de `answers`.
     - Em `switchView("report")`, sempre resetar `selectedReportRunId` para a **última execução**.
     - Renderizar seletor de execuções + gráfico SVG `passRateEvolutionChart` + relatório integral baseado no snapshot selecionado (incluindo `exportJson` e `print`).
3. **Validação:**
   - Criar `test_iteration195_report_pass_evolution_and_history` em `casa-assessment/tests/test_neon_reeval.py` validando CRUD `/api/applications/history`, persistência de múltiplas execuções ordenadas, gráfico SVG + seletor no frontend e `node --check`.
   - Reiniciar servidor `casa_audit` na porta `8080`, documentar em `docs/justificativaNeon.txt`, commitar, criar tag `sdd-195` e fazer push.

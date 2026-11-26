# SDD 195 — Evolução da Taxa de Sucesso (Pass) e Histórico de Relatórios por Execução de Scan

## Requisitos do Usuário
1. Exibir na guia **Relatório** a **evolução da taxa de Sucesso (Pass)** conforme as datas de execução de scan na Aplicação selecionada.
2. Na guia **Relatório**, trazer **sempre o resultado da última execução de Scan** por padrão.
3. Permitir que o usuário **selecione um relatório executado em outro momento** (via seletor de execuções, botões Anterior/Próxima/Última ou clicando diretamente nos pontos do gráfico de evolução).

## Arquitetura
- **Backend (`casa-assessment/casa_audit/server.py`):**
  - Persistência thread-safe em `casa-assessment/output/scan_history.json` (indexado por `app_id`):
    - `GET /api/applications/history?app_id=<id>` — retorna lista cronológica de execuções (`runs`).
    - `POST /api/applications/history` — grava snapshot imutável de execução (`id`, `executedAt`, `date`, `source`, `target`, `surfaces`, `summary`, `answers`).
    - `DELETE /api/applications/history?app_id=<id>` — remove histórico da aplicação (também acionado ao excluir a aplicação).
- **Frontend (`assess.html`, `styles.css`, `app.js`):**
  - Cada conclusão de scan (`applyScanResults`) grava um snapshot completo em `localStorage` (`casa3-app-history-<appId>`) e sincroniza via `POST /api/applications/history`.
  - Ao abrir a guia **Relatório**, seleciona sempre a **última execução** (`runs[runs.length - 1]`).
  - Barra de seleção histórica (`.report-history-bar`) com `<select id="report-run-select">`, botões `◀ Anterior`, `Próxima ▶`, badge de visualização histórica e atalho `Ver Última Execução`.
  - Gráfico SVG interativo **Evolução da Taxa de Sucesso (Pass Rate)** (`passRateEvolutionChart`) com eixo temporal por data/hora de scan, linha/área de tendência, badge de variação (`delta %`), pontos clicáveis para alternar diretamente para o relatório daquela execução e suporte completo a i18n (`PT`/`EN`).
  - Cache-busting atualizado para `?v=sdd195`.

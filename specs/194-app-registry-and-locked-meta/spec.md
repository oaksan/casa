# SDD 194 — Pré-Cadastro e Seleção de Aplicação, Metadados Bloqueados e Data Automática do Scan

## Requisitos do Usuário
1. Permitir **selecionar a APLICAÇÃO ANTES** de iniciar a **Avaliação** e visualizar o **Relatório**.
2. Caso a aplicação ainda não tenha sido cadastrada, permitir **cadastrá-la previamente** (e editar/excluir aplicações cadastradas).
3. **AVALIADOR** e **NÍVEL ALVO** (`AL1` / `AL2`) **não podem ser alterados** dentro das guias **Avaliação** e **Relatório** — somente podem ser alterados dentro do **cadastro da APLICAÇÃO**.
4. A **Data da Avaliação** deve ser **preenchida automaticamente após a conclusão de um scan**, não sendo um campo selecionável/editável manualmente.

## Arquitetura
- **Backend (`casa-assessment/casa_audit/server.py`):**
  - Endpoints REST persistidos em `casa-assessment/output/applications.json`:
    - `GET /api/applications` — lista aplicações cadastradas.
    - `POST /api/applications` — cadastra ou atualiza aplicação (validando `org`, `assessor` e `target` ∈ `{AL1, AL2}`).
    - `DELETE /api/applications?id=<id>` — remove aplicação cadastrada.
- **Frontend (`assess.html`, `styles.css`, `app.js`):**
  - Nova aba inicial **Aplicações** (`#view-apps`) posicionada antes de **Avaliação** (`#view-assess`) e **Relatório** (`#view-report`).
  - As abas **Avaliação** e **Relatório** permanecem bloqueadas (`disabled`) enquanto nenhuma aplicação estiver selecionada.
  - Cada aplicação cadastrada mantém seu próprio estado isolado de avaliação (respostas, logs, notas, checklists e data do último scan) em `localStorage` + sincronização com `/api/applications`.
  - Na guia **Avaliação**, o card de metadados exibe `Aplicação`, `Avaliador`, `Data da Avaliação` e `Nível de Garantia Alvo` como campos **estritamente somente leitura** (sem `<input>`, sem `<select>`, sem `<input type="date">`), com atalho para gerenciar no cadastro de Aplicações.
  - A **Data da Avaliação** inicia vazia (`"Preenchida automaticamente após o scan"`) e é gravada automaticamente ao concluir o scan em `applyScanResults(...)`.
  - Suporte completo a i18n (`PT`/`EN`) e cache-busting `?v=sdd194`.

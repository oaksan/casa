# Plano — SDD 194 (Cadastro/Seleção de Aplicações, Metadados Bloqueados e Data Automática)

1. **`casa-assessment/casa_audit/server.py`:**
   - Adicionar persistência thread-safe em `OUTPUT_DIR / "applications.json"` e rotas `GET /api/applications`, `POST /api/applications` e `DELETE /api/applications?id=<id>`.
2. **`casa-assessment/frontend/assess.html`:**
   - Adicionar aba `Aplicações` (`data-view="apps"`) como primeira aba na `.view-switch`, bloqueando inicialmente `Avaliação` e `Relatório`.
   - Adicionar seção `#view-apps` com formulário de cadastro/edição (`org`, `assessor`, `target`, `targetUrl`, `repoPath`, `surfaces`) e lista de aplicações cadastradas.
   - Substituir `<input id="org">`, `<input id="assessor">`, `<input id="date" type="date">` e `<select id="target">` em `#view-assess` por displays somente leitura (`#org-display`, `#assessor-display`, `#date-display`, `#target-display`) com aviso de bloqueio e botão "Gerenciar / Trocar Aplicação".
   - Atualizar `?v=sdd194` nos assets estáticos.
3. **`casa-assessment/frontend/styles.css` & `app.js`:**
   - Estilizar `#view-apps`, cards de aplicação, badges `AL1`/`AL2`, campos `.readonly-field` com ícone de cadeado e abas desabilitadas.
   - Implementar gerenciamento de aplicações com isolamento de respostas por aplicação, bloqueio de `switchView("assess"|"report")` sem aplicação selecionada, preenchimento automático de `date` / `lastScanAt` apenas ao concluir um scan, e suporte completo `PT`/`EN`.
4. **Validação:**
   - Adicionar `test_iteration194_app_registry_and_locked_meta` em `casa-assessment/tests/test_neon_reeval.py` validando CRUD `/api/applications`, ausência de `<input type="date">` e inputs editáveis de `assessor`/`target` em `#view-assess`, bloqueio de abas e sintaxe `node --check`.
   - Reiniciar servidor `casa_audit` na porta `8080`, documentar em `docs/justificativaNeon.txt`, commitar, criar tag `sdd-194` e fazer push.

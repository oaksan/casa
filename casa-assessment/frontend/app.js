/* ADA CASA 3.0 Assessment Frontend - Vanilla JS, localStorage + IndexedDB + Automated AL1 Engine + PT/EN i18n */
(function () {
  "use strict";

  var DATA = window.CASA3_DATA;
  var STORE_KEY = "casa3-assessment-v1";
  var APPS_STORE_KEY = "casa3-applications-v1";
  var ACTIVE_APP_KEY = "casa3-active-app-v1";
  var APP_STATE_PREFIX = "casa3-app-state-";
  var APP_HISTORY_PREFIX = "casa3-app-history-";
  var LANG_STORE_KEY = "casa3-lang-v1";

  var I18N = {
    pt: {
      brandSub: "Avaliação de Segurança de Aplicações Web",
      resetBtn: "Limpar",
      resetTitle: "Limpar os vereditos, execuções, notas e capturas da aplicação selecionada",
      tabApps: "Aplicações",
      tabAssess: "Avaliação",
      tabReport: "Relatório",
      tabLockedTitle: "Selecione ou cadastre uma aplicação antes de acessar esta guia",
      appsKicker: "App Defense Alliance · Linux Foundation · v3.0",
      appsTitle: "Aplicações CASA 3.0",
      appsLede:
        "Selecione uma aplicação cadastrada para iniciar a <strong>Avaliação</strong> ou visualizar o <strong>Relatório</strong>. Caso a aplicação ainda não exista, cadastre-a abaixo — <strong>Avaliador</strong> e <strong>Nível de Garantia Alvo</strong> são definidos exclusivamente neste cadastro.",
      appsListTitle: "Aplicações Cadastradas",
      appsListSub: "Escolha uma aplicação para liberar as guias Avaliação e Relatório.",
      appsEmpty: "Nenhuma aplicação cadastrada ainda. Cadastre a primeira aplicação abaixo para iniciar.",
      btnFocusNewApp: "+ Cadastrar Nova Aplicação",
      appFormTitleNew: "Cadastrar Nova Aplicação",
      appFormTitleEdit: "Editar Aplicação Cadastrada",
      appFormSub: "Preencha os dados da aplicação, o avaliador responsável e o nível de garantia alvo (AL1 ou AL2).",
      appLblOrg: "Aplicação / Organização *",
      appLblAssessor: "Avaliador / Laboratório *",
      appLblTarget: "Nível de Garantia Alvo *",
      appBtnCreate: "Cadastrar Aplicação",
      appBtnSave: "Salvar Alterações",
      appBtnCancelEdit: "Cancelar Edição",
      appErrOrg: "Informe o nome da Aplicação / Organização.",
      appErrAssessor: "Informe o Avaliador / Laboratório.",
      appBadgeSelected: "Selecionada",
      appCardAssessor: "Avaliador:",
      appCardLastScan: "Último scan:",
      appCardNoScan: "Aguardando scan",
      appCardUrl: "URL:",
      appCardSurfaces: "Superfícies:",
      appActAssess: "▶ Iniciar Avaliação",
      appActReport: "Ver Relatório",
      appActEdit: "Editar",
      appActDelete: "Excluir",
      appConfirmDelete: function (name) {
        return 'Excluir a aplicação "' + name + '" e seus dados de avaliação salvos neste navegador?';
      },
      gateNotice: "Selecione uma aplicação cadastrada (ou cadastre uma nova abaixo) antes de acessar Avaliação ou Relatório.",
      setupLockHint:
        "Avaliador e Nível Alvo só podem ser alterados no cadastro da Aplicação. A Data da Avaliação é preenchida automaticamente após a conclusão do scan.",
      btnManageApps: "← Trocar / Editar Aplicação",
      datePendingScan: "Preenchida automaticamente após o scan",
      reportNoScanDate: "Scan ainda não concluído",
      btnBackApps: "← Aplicações",
      repHistLabel: "Execução do Scan:",
      repHistLatestTag: "Última execução",
      repHistPrev: "◀ Anterior",
      repHistNext: "Próxima ▶",
      repHistGoLatest: "Ver Última Execução →",
      repHistNoRuns: "Nenhum scan registrado ainda",
      repHistBanner: function (idx, total, dt) {
        return "Visualizando relatório histórico — Execução #" + idx + " de " + total + " (" + dt + ").";
      },
      secEvolution: "Evolução da Taxa de Sucesso (Pass) por Data de Scan",
      evoTitle: "Histórico de Taxa de Aprovação (PASS %)",
      evoEmpty: "Execute ao menos um scan automatizado para registrar o histórico e acompanhar a evolução da taxa de sucesso.",
      evoSingleHint: "1 execução registrada (linha de base). Execute novos scans após correções para visualizar a curva de evolução.",
      evoMultiHint: "Clique em qualquer ponto do gráfico ou use o seletor acima para abrir o relatório completo daquela execução.",
      evoRunsCount: function (n) {
        return n + (n === 1 ? " execução" : " execuções");
      },
      heroKicker: "App Defense Alliance · Linux Foundation · v3.0",
      heroTitle: "Avaliação CASA 3.0",
      heroLede:
        "Avalie aplicações web contra os 8 domínios da especificação CASA 3.0. O <strong>AL1</strong> (61 controles) é avaliado automaticamente por sinais determinísticos de aprovação/falha e formatos abertos de evidência (SARIF, CycloneDX, HAR). O <strong>AL2</strong> (+15 controles) adiciona checklists de evidências de verificação adjudicadas em laboratório, notas do avaliador e capturas de tela.",
      lblOrg: "Aplicação / Organização",
      phOrg: "ex.: OWASP Juice Shop",
      lblAssessor: "Avaliador / Laboratório",
      phAssessor: "ex.: Laboratório de Pesquisa Mestrado",
      lblDate: "Data da Avaliação",
      lblTarget: "Nível de Garantia Alvo",
      optAL1: "AL1 — Avaliação Automatizada (61 Controles)",
      optAL2: "AL2 — Avaliação Completa de Lab (61 AL1 + 15 AL2)",
      pillAuto: "Motor Automatizado AL1",
      autoTitle: "Execução Automatizada AL1",
      surfacesLbl: "Superfícies Declaradas:",
      lblUrl: "URL da Aplicação Alvo (para TLS, Headers, Cookies, DAST)",
      lblRepo: "Caminho do Repositório / Artefato (para SCA, SAST, Segredos)",
      btnRunAuto: "▶ Executar Scan Automatizado AL1",
      btnRunAutoBusy: "⏳ Escaneando AL1…",
      statusReady: "Pronto — 61 controles AL1 aguardando execução automatizada.",
      statusRunning: "Executando verificações automatizadas do AL1 (SCA, SAST, TLS, CFG, AUT, AZI, OAU, WHK)…",
      scanLastPrefix: "Último controle:",
      scanWaitingCtrl: "Aguardando primeiro controle…",
      scanErrorPrefix: "Erro durante o scan:",
      fltAll: "Todos no Escopo",
      fltAL1: "AL1 Automatizados (61)",
      fltAL2: "AL2 Checklist Manual (15)",
      fltFail: "Reprovados",
      resetAllBtn: "Limpar todas as respostas",
      gotoReportBtn: "Gerar Relatório CASA 3.0 →",
      footTxt: "App Defense Alliance · Avaliação de Segurança de Aplicações Web CASA 3.0 (Mestrado)",
      footLink: "Projeto no GitHub",
      railTitle: "Domínios CASA 3.0",
      verdicts: [
        { key: null, code: "–", label: "Não definido" },
        { key: "PASS", code: "PASS", label: "Conforme" },
        { key: "FAIL", code: "FAIL", label: "Não conforme" },
        { key: "NOT_APPLICABLE", code: "N/A", label: "Fora de escopo" },
        { key: "Not_Covered", code: "N/C", label: "Não coberto" },
      ],
      badgeAL1: "AL1 · Automatizado",
      badgeAL2: "AL2 · Adjudicado pelo Lab",
      refTooling: "Ferramentas de Referência:",
      specClosed: "Especificação e Critérios de Pass/Fail ›",
      specOpen: "Ocultar Especificação e Critérios ‹",
      passSignal: "Sinal de PASS (Conforme)",
      failSignal: "Sinal de FAIL (Não Conforme)",
      reqEvidence: "Evidência Exigida:",
      testProc: "Procedimento de Teste:",
      autoLogHead: "Evidência Automatizada e Sinal da Ferramenta",
      triageNotesLbl: "Notas do Avaliador",
      triageNotesPh: "Notas como controles compensatórios",
      verifEvidence: "Evidências de verificação",
      notesLbl: "Notas",
      notesPh: "Contexto, ressalvas, links para evidências HAR/SARIF, detalhes de contas de teste…",
      screenshotsTitle: "Capturas de tela de evidência",
      addScreenshot: "Adicionar captura",
      dragScreenshots: "Arraste capturas de tela aqui, ou clique em Adicionar captura.",
      figCaptionPh: "Descreva o que esta captura de tela demonstra…",
      removeFig: "Remover",
      controlsCount: function (total, al1, al2) {
        return (
          total +
          " controles (" +
          al1 +
          " AL1 automatizados" +
          (al2 ? " + " + al2 + " AL2 manuais" : "") +
          ")"
        );
      },
      progressCount: function (done, total, target) {
        return done + " de " + total + " avaliados (" + target + ")";
      },
      progressBreakdown: function (al1Done, al1All, al2Done, al2All) {
        return (
          "AL1 Automatizado: " +
          al1Done +
          "/" +
          al1All +
          (al2All ? " · AL2 Manual: " + al2Done + "/" + al2All : "")
        );
      },
      emptyFilter: "Nenhum controle corresponde ao filtro selecionado.",
      confirmReset:
        "Limpar todos os vereditos, logs de scan automatizado, itens de checklist, notas e capturas de tela salvos neste navegador? Esta ação não pode ser desfeita.",
      reportTitle: "Relatório de Conformidade ADA CASA 3.0",
      certPass: function (t) {
        return "EM CONFORMIDADE (" + t + ")";
      },
      certFail: function (n) {
        return "CORREÇÃO NECESSÁRIA (" + n + " Bloqueante" + (n > 1 ? "s" : "") + ")";
      },
      certInc: "Avaliação Incompleta",
      statEval: "Controles avaliados",
      statPassRate: "Taxa de aprovação (aplicáveis)",
      statAL1: "AL1 Automatizados (PASS/NA)",
      statAL2: "AL2 Adjudicados pelo Lab (PASS/NA)",
      secOverview: "Visão Geral de Conformidade",
      donutCap: "Conformidade geral CASA 3.0",
      secPipeline: "Conformidade nos 8 Domínios do CASA 3.0",
      pipelineCap:
        "Domínios desde cadeia de suprimentos e análise estática até transporte, configuração, autenticação, autorização, OAuth e webhooks. Tons mais escuros indicam maior conformidade.",
      secFindings: function (failN, notEvalN, figN) {
        return (
          "Achados Bloqueantes para Correção · " +
          failN +
          " reprovado(s) / não coberto(s)" +
          (notEvalN ? " · " + notEvalN + " ainda não avaliado(s)" : "") +
          (figN ? " · " + figN + " captura" + (figN > 1 ? "s" : "") + " de tela" : "")
        );
      },
      emptyReportNoEval:
        "Nenhum controle avaliado ainda. Execute o Scan Automatizado AL1 ou avalie os controles do AL2 para gerar o relatório.",
      emptyReportAllPass: function (t) {
        return (
          "Zero falhas bloqueantes! Todos os controles avaliados atendem aos critérios de aceitação do CASA 3.0 (" +
          t +
          ")."
        );
      },
      reqPassToFix: "Critério de PASS Exigido para Correção:",
      assessorNote: "Nota do Avaliador:",
      suppEvidence: "Evidência de Apoio:",
      secScreenshots: "Evidências em Capturas de Tela do AL2",
      noCaption: "Nenhuma descrição informada",
      btnBack: "← Voltar para avaliação",
      btnExport: "Exportar JSON CASA 3.0",
      btnPrint: "Imprimir / Salvar Relatório PDF",
    },
    en: {
      brandSub: "Cloud Application Security Assessment",
      resetBtn: "Reset",
      resetTitle: "Clear saved verdicts, automated runs, notes and screenshots for the selected application",
      tabApps: "Applications",
      tabAssess: "Assessment",
      tabReport: "Report",
      tabLockedTitle: "Select or register an application before accessing this tab",
      appsKicker: "App Defense Alliance · Linux Foundation · v3.0",
      appsTitle: "CASA 3.0 Applications",
      appsLede:
        "Select a registered application before starting an <strong>Assessment</strong> or viewing a <strong>Report</strong>. If the application does not exist yet, register it below — <strong>Assessor</strong> and <strong>Target Assurance Level</strong> can only be changed here.",
      appsListTitle: "Registered Applications",
      appsListSub: "Choose an application to unlock the Assessment and Report tabs.",
      appsEmpty: "No applications registered yet. Register your first application below to begin.",
      btnFocusNewApp: "+ Register New Application",
      appFormTitleNew: "Register New Application",
      appFormTitleEdit: "Edit Registered Application",
      appFormSub: "Provide application details, responsible assessor, and target assurance level (AL1 or AL2).",
      appLblOrg: "Application / Organization *",
      appLblAssessor: "Assessor / Security Lab *",
      appLblTarget: "Target Assurance Level *",
      appBtnCreate: "Register Application",
      appBtnSave: "Save Changes",
      appBtnCancelEdit: "Cancel Edit",
      appErrOrg: "Please enter the Application / Organization name.",
      appErrAssessor: "Please enter the Assessor / Security Lab.",
      appBadgeSelected: "Selected",
      appCardAssessor: "Assessor:",
      appCardLastScan: "Last scan:",
      appCardNoScan: "Awaiting scan",
      appCardUrl: "URL:",
      appCardSurfaces: "Surfaces:",
      appActAssess: "▶ Start Assessment",
      appActReport: "View Report",
      appActEdit: "Edit",
      appActDelete: "Delete",
      appConfirmDelete: function (name) {
        return 'Delete application "' + name + '" and its saved assessment data in this browser?';
      },
      gateNotice: "Select a registered application (or register a new one below) before accessing Assessment or Report.",
      setupLockHint:
        "Assessor and Target Level can only be changed in the Application registry. Evaluation Date is filled automatically after scan completion.",
      btnManageApps: "← Switch / Edit Application",
      datePendingScan: "Auto-filled after scan completion",
      reportNoScanDate: "Scan not yet completed",
      btnBackApps: "← Applications",
      repHistLabel: "Scan Execution:",
      repHistLatestTag: "Latest run",
      repHistPrev: "◀ Previous",
      repHistNext: "Next ▶",
      repHistGoLatest: "View Latest Run →",
      repHistNoRuns: "No scan runs recorded yet",
      repHistBanner: function (idx, total, dt) {
        return "Viewing historical report — Run #" + idx + " of " + total + " (" + dt + ").";
      },
      secEvolution: "Pass Rate Evolution Across Scan Dates",
      evoTitle: "Pass Rate History (PASS %)",
      evoEmpty: "Run at least one automated scan to record history and track pass-rate evolution over time.",
      evoSingleHint: "1 scan run recorded (baseline). Run additional scans after fixes to visualize the evolution curve.",
      evoMultiHint: "Click any point on the chart or use the selector above to inspect the full report from that run.",
      evoRunsCount: function (n) {
        return n + (n === 1 ? " run" : " runs");
      },
      heroKicker: "App Defense Alliance · Linux Foundation · v3.0",
      heroTitle: "CASA 3.0 Assessment",
      heroLede:
        "Evaluate web applications against the 8 domains of the CASA 3.0 specification. <strong>AL1</strong> (61 controls) is evaluated automatically via deterministic pass/fail signals and open evidence formats (SARIF, CycloneDX, HAR). <strong>AL2</strong> (+15 controls) adds lab-adjudicated verification evidence checklists, assessor notes, and evidence screenshots.",
      lblOrg: "Application / Organization",
      phOrg: "e.g. OWASP Juice Shop",
      lblAssessor: "Assessor / Security Lab",
      phAssessor: "e.g. Master's Research Lab",
      lblDate: "Date of Evaluation",
      lblTarget: "Target Assurance Level",
      optAL1: "AL1 — Automated Assessment (61 Controls)",
      optAL2: "AL2 — Full Lab Assessment (61 AL1 + 15 AL2)",
      pillAuto: "AL1 Automated Engine",
      autoTitle: "Automated AL1 Execution",
      surfacesLbl: "Declared Surfaces:",
      lblUrl: "Target Application URL (for TLS, Headers, Cookies, DAST)",
      lblRepo: "Source Repository / Artifact Path (for SCA, SAST, Secrets)",
      btnRunAuto: "▶ Run Automated AL1 Scan",
      btnRunAutoBusy: "⏳ Scanning AL1…",
      statusReady: "Ready — 61 AL1 controls awaiting automated scan.",
      statusRunning: "Running automated AL1 checks (SCA, SAST, TLS, CFG, AUT, AZI, OAU, WHK)…",
      scanLastPrefix: "Last control:",
      scanWaitingCtrl: "Waiting for first control…",
      scanErrorPrefix: "Scan error:",
      fltAll: "All in Scope",
      fltAL1: "AL1 Automated (61)",
      fltAL2: "AL2 Manual Checklist (15)",
      fltFail: "Failing",
      resetAllBtn: "Reset all answers",
      gotoReportBtn: "Generate CASA 3.0 Report →",
      footTxt: "App Defense Alliance · CASA 3.0 Web Application Security Assessment",
      footLink: "Project on GitHub",
      railTitle: "CASA 3.0 Domains",
      verdicts: [
        { key: null, code: "–", label: "Not set" },
        { key: "PASS", code: "PASS", label: "Compliant" },
        { key: "FAIL", code: "FAIL", label: "Non-compliant" },
        { key: "NOT_APPLICABLE", code: "N/A", label: "Out of scope" },
        { key: "Not_Covered", code: "N/C", label: "Not covered" },
      ],
      badgeAL1: "AL1 · Automated",
      badgeAL2: "AL2 · Lab-Adjudicated",
      refTooling: "Reference Tooling:",
      specClosed: "Specification & Pass/Fail Criteria ›",
      specOpen: "Hide Specification & Criteria ‹",
      passSignal: "PASS Signal",
      failSignal: "FAIL Signal",
      reqEvidence: "Required Evidence:",
      testProc: "Test Procedure:",
      autoLogHead: "Automated Evidence & Tool Signal",
      triageNotesLbl: "Assessor Notes",
      triageNotesPh: "Notes such as compensating controls",
      verifEvidence: "Verification evidence",
      notesLbl: "Notes",
      notesPh: "Context, caveats, links to HAR/SARIF evidence, test account details…",
      screenshotsTitle: "Evidence screenshots",
      addScreenshot: "Add screenshot",
      dragScreenshots: "Drag screenshots here, or use Add screenshot.",
      figCaptionPh: "Describe what this screenshot shows…",
      removeFig: "Remove",
      controlsCount: function (total, al1, al2) {
        return (
          total +
          " controls (" +
          al1 +
          " AL1 automated" +
          (al2 ? " + " + al2 + " AL2 manual" : "") +
          ")"
        );
      },
      progressCount: function (done, total, target) {
        return done + " of " + total + " assessed (" + target + ")";
      },
      progressBreakdown: function (al1Done, al1All, al2Done, al2All) {
        return (
          "AL1 Automated: " +
          al1Done +
          "/" +
          al1All +
          (al2All ? " · AL2 Manual: " + al2Done + "/" + al2All : "")
        );
      },
      emptyFilter: "No controls match the selected filter.",
      confirmReset:
        "Clear every verdict, automated scan log, checklist item, note and screenshot stored in this browser? This cannot be undone.",
      reportTitle: "ADA CASA 3.0 Compliance Report",
      certPass: function (t) {
        return "IN COMPLIANCE (" + t + ")";
      },
      certFail: function (n) {
        return "REMEDIATION REQUIRED (" + n + " Blocking)";
      },
      certInc: "Assessment Incomplete",
      statEval: "Controls evaluated",
      statPassRate: "Pass rate (applicable)",
      statAL1: "AL1 Automated (PASS/NA)",
      statAL2: "AL2 Lab-Adjudicated (PASS/NA)",
      secOverview: "Compliance Overview",
      donutCap: "Overall CASA 3.0 compliance",
      secPipeline: "Compliance across the 8 CASA 3.0 Domains",
      pipelineCap:
        "Domains from supply chain & static code analysis through transport, configuration, authentication, authorization, OAuth, and webhooks. Darker indicates higher compliance.",
      secFindings: function (failN, notEvalN, figN) {
        return (
          "Blocking Remediation Findings · " +
          failN +
          " failing / not covered" +
          (notEvalN ? " · " + notEvalN + " not yet evaluated" : "") +
          (figN ? " · " + figN + " screenshot" + (figN > 1 ? "s" : "") : "")
        );
      },
      emptyReportNoEval:
        "No controls evaluated yet. Run the Automated AL1 Scan or rate AL2 controls to generate findings.",
      emptyReportAllPass: function (t) {
        return "Zero blocking failures! All evaluated controls meet CASA 3.0 (" + t + ") acceptance criteria.";
      },
      reqPassToFix: "Required PASS Criterion to Remediate:",
      assessorNote: "Assessor Note:",
      suppEvidence: "Supporting Evidence:",
      secScreenshots: "Supporting AL2 Screenshot Evidence",
      noCaption: "No description provided",
      btnBack: "← Back to assessment",
      btnExport: "Export CASA 3.0 JSON",
      btnPrint: "Print / Save PDF Report",
    },
  };

  var SHORT_DOMAIN = {
    "Software Composition & Supply Chain": "SCA",
    "Static Code Analysis & Secrets": "SAST",
    "Transport Security": "TLS",
    "Server Configuration & Response Headers": "CFG",
    "Authentication & Session Management": "AUT",
    "Authorization & Injection": "AZI",
    "Application Use of OAuth 2.0 / OpenID Connect": "OAU",
    "Webhook Security": "WHK",
  };

  if (!DATA || !Array.isArray(DATA.controls)) {
    document.getElementById("controls").innerHTML =
      '<div class="card empty">Could not load CASA 3.0 specification data.</div>';
    return;
  }

  /* ---------- application registry & per-app state (SDD 194) ---------- */
  var apps = loadAppsLocal();
  var activeAppId = null;
  var editingAppId = "";
  var currentView = "apps";
  var activeFilter = "all";
  var appScanHistory = [];
  var selectedReportRunId = null;
  var state = createEmptyState();

  function cloneJson(obj) {
    try {
      return JSON.parse(JSON.stringify(obj || {}));
    } catch (e) {
      return {};
    }
  }

  function computeAnswersSummary(answersMap, targetLevel) {
    var tgt = targetLevel === "AL1" ? "AL1" : "AL2";
    var inScope = DATA.controls.filter(function (c) {
      return tgt === "AL1" ? c.tier === "AL1" : true;
    });
    var assessed = 0,
      applicable = 0,
      passed = 0,
      failed = 0,
      notCovered = 0,
      na = 0;
    inScope.forEach(function (c) {
      var a = answersMap && answersMap[c.id];
      if (!a || a.verdict == null) return;
      assessed++;
      if (a.verdict === "NOT_APPLICABLE") {
        na++;
      } else {
        applicable++;
        if (a.verdict === "PASS") passed++;
        else if (a.verdict === "FAIL") failed++;
        else if (a.verdict === "Not_Covered") notCovered++;
      }
    });
    var rate = applicable ? passed / applicable : 0;
    return {
      passRate: Math.round(rate * 10000) / 10000,
      passPct: Math.round(rate * 100),
      passedCount: passed,
      applicableCount: applicable,
      assessedCount: assessed,
      inScopeCount: inScope.length,
      failCount: failed,
      notCoveredCount: notCovered,
      naCount: na,
    };
  }

  function loadAppHistoryLocal(appId, appObj, currentAnswers) {
    var list = [];
    if (!appId) return list;
    try {
      var raw = localStorage.getItem(APP_HISTORY_PREFIX + appId);
      if (raw) {
        var parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          list = parsed.filter(function (r) {
            return r && r.id;
          });
        }
      }
    } catch (e) {}

    // Auto-seed an initial historical run if an app already has a completed scan from before SDD 195
    if (!list.length && appObj && (appObj.lastScanAt || appObj.date)) {
      var ans = currentAnswers || loadAppAnswers(appId);
      var hasVerdict = Object.keys(ans).some(function (k) {
        return ans[k] && ans[k].verdict != null;
      });
      if (hasVerdict) {
        var execIso = appObj.lastScanAt || (appObj.date ? appObj.date + "T12:00:00Z" : new Date().toISOString());
        var seedRun = {
          id: "run-seed-" + appId,
          appId: appId,
          executedAt: execIso,
          date: appObj.date || execIso.slice(0, 10),
          source: "ada-casa-audit Live Scanner",
          target: appObj.target === "AL1" ? "AL1" : "AL2",
          surfaces: (appObj.surfaces || ["Web_Application"]).slice(),
          summary: computeAnswersSummary(ans, appObj.target),
          answers: cloneJson(ans),
        };
        list = [seedRun];
        saveAppHistoryLocal(appId, list);
      }
    }
    list.sort(function (a, b) {
      return String(a.executedAt || a.date || "").localeCompare(String(b.executedAt || b.date || ""));
    });
    return list;
  }

  function saveAppHistoryLocal(appId, runs) {
    if (!appId) return;
    try {
      localStorage.setItem(APP_HISTORY_PREFIX + appId, JSON.stringify(runs || []));
    } catch (e) {}
  }

  function pushRunHistoryToServer(appId, runObj) {
    if (!appId || !runObj) return Promise.resolve();
    return fetch("/api/applications/history", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ app_id: appId, run: runObj }),
    }).catch(function () {});
  }

  function fetchAppHistoryFromServer(appId) {
    if (!appId) return Promise.resolve();
    return fetch("/api/applications/history?app_id=" + encodeURIComponent(appId), { cache: "no-store" })
      .then(function (r) {
        return r.ok ? r.json() : null;
      })
      .then(function (data) {
        if (!data || !Array.isArray(data.runs) || activeAppId !== appId) return;
        var byId = {};
        data.runs.forEach(function (sr) {
          if (sr && sr.id) byId[sr.id] = sr;
        });
        appScanHistory.forEach(function (lr) {
          if (lr && lr.id && !byId[lr.id]) {
            byId[lr.id] = lr;
            pushRunHistoryToServer(appId, lr);
          }
        });
        appScanHistory = Object.keys(byId).map(function (k) {
          return byId[k];
        });
        appScanHistory.sort(function (a, b) {
          return String(a.executedAt || a.date || "").localeCompare(String(b.executedAt || b.date || ""));
        });
        saveAppHistoryLocal(appId, appScanHistory);
        if (
          !selectedReportRunId ||
          !appScanHistory.some(function (r) {
            return r.id === selectedReportRunId;
          })
        ) {
          selectedReportRunId = appScanHistory.length ? appScanHistory[appScanHistory.length - 1].id : null;
        }
        if (currentView === "report") {
          buildReport();
        }
      })
      .catch(function () {});
  }

  function recordScanRunSnapshot(sourceLabel, nowDate) {
    if (!activeAppId) return;
    var now = nowDate || new Date();
    var isoFull = now.toISOString();
    var isoDate = today();
    var tgt = state.meta.target === "AL1" ? "AL1" : "AL2";
    var ansCopy = cloneJson(state.answers);
    var runRec = {
      id: "run-" + now.getTime().toString(36) + "-" + Math.random().toString(36).slice(2, 6),
      appId: activeAppId,
      executedAt: isoFull,
      date: isoDate,
      source: sourceLabel || "ada-casa-audit Live Scanner",
      target: tgt,
      surfaces: (state.meta.surfaces || ["Web_Application"]).slice(),
      summary: computeAnswersSummary(ansCopy, tgt),
      answers: ansCopy,
    };
    appScanHistory.push(runRec);
    appScanHistory.sort(function (a, b) {
      return String(a.executedAt || a.date || "").localeCompare(String(b.executedAt || b.date || ""));
    });
    if (appScanHistory.length > 100) {
      appScanHistory = appScanHistory.slice(-100);
    }
    selectedReportRunId = runRec.id;
    saveAppHistoryLocal(activeAppId, appScanHistory);
    pushRunHistoryToServer(activeAppId, runRec);
  }

  function formatShortChartDate(isoDate, executedAt) {
    var isPt = lang() === "pt";
    if (executedAt) {
      var d = new Date(executedAt);
      if (!isNaN(d.getTime())) {
        var dd = pad(d.getDate());
        var mm = pad(d.getMonth() + 1);
        var hh = pad(d.getHours());
        var mi = pad(d.getMinutes());
        return (isPt ? dd + "/" + mm : mm + "-" + dd) + " " + hh + ":" + mi;
      }
    }
    if (isoDate && /^\d{4}-\d{2}-\d{2}$/.test(isoDate)) {
      var p = isoDate.split("-");
      return isPt ? p[2] + "/" + p[1] : p[1] + "-" + p[2];
    }
    return isoDate || "—";
  }

  function getSavedLang() {
    try {
      var l = localStorage.getItem(LANG_STORE_KEY);
      if (l === "en" || l === "pt") return l;
    } catch (e) {}
    return "pt";
  }

  function createEmptyState(app) {
    var a = app || {};
    return {
      meta: {
        appId: a.id || "",
        lang: getSavedLang(),
        org: a.org || "",
        assessor: a.assessor || "",
        date: a.date || "",
        lastScanAt: a.lastScanAt || "",
        target: a.target === "AL1" ? "AL1" : "AL2",
        targetUrl: a.targetUrl != null ? a.targetUrl : "http://localhost:3000",
        repoPath: a.repoPath != null ? a.repoPath : "/home/user/felipe/speckit/juice-shop-master",
        surfaces: Array.isArray(a.surfaces) && a.surfaces.length ? a.surfaces.slice() : ["Web_Application"],
      },
      answers: {},
    };
  }

  function loadAppsLocal() {
    var list = [];
    try {
      var raw = localStorage.getItem(APPS_STORE_KEY);
      if (raw) {
        var parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          list = parsed.filter(function (x) {
            return x && x.id && x.org;
          });
        }
      }
    } catch (e) {}

    // One-time migration from legacy single-app storage if no registered apps exist yet
    if (!list.length) {
      try {
        var legacyRaw = localStorage.getItem(STORE_KEY);
        if (legacyRaw) {
          var legacy = JSON.parse(legacyRaw);
          var lm = (legacy && legacy.meta) || {};
          var la = (legacy && legacy.answers) || {};
          var hasAnswers = Object.keys(la).some(function (k) {
            return la[k] && la[k].verdict != null;
          });
          if (lm.org || lm.assessor || hasAnswers) {
            var migId = "app-migrated-1";
            var scanTs = "";
            Object.keys(la).forEach(function (k) {
              if (!scanTs && la[k] && la[k].autoTimestamp) scanTs = la[k].autoTimestamp;
            });
            var migApp = {
              id: migId,
              org: lm.org || "OWASP Juice Shop",
              assessor: lm.assessor || "Avaliador",
              target: lm.target === "AL1" ? "AL1" : "AL2",
              targetUrl: lm.targetUrl || "http://localhost:3000",
              repoPath: lm.repoPath || "/home/user/felipe/speckit/juice-shop-master",
              surfaces: Array.isArray(lm.surfaces) && lm.surfaces.length ? lm.surfaces : ["Web_Application"],
              date: scanTs ? scanTs.slice(0, 10) : "",
              lastScanAt: scanTs || "",
            };
            list = [migApp];
            localStorage.setItem(APPS_STORE_KEY, JSON.stringify(list));
            localStorage.setItem(APP_STATE_PREFIX + migId, JSON.stringify({ answers: la }));
          }
        }
      } catch (e) {}
    }
    return list;
  }

  function saveAppsLocal() {
    try {
      localStorage.setItem(APPS_STORE_KEY, JSON.stringify(apps));
    } catch (e) {}
  }

  function getAppById(id) {
    if (!id) return null;
    for (var i = 0; i < apps.length; i++) {
      if (apps[i].id === id) return apps[i];
    }
    return null;
  }

  function loadAppAnswers(appId) {
    if (!appId) return {};
    try {
      var raw = localStorage.getItem(APP_STATE_PREFIX + appId);
      if (raw) {
        var parsed = JSON.parse(raw);
        return (parsed && parsed.answers) || {};
      }
    } catch (e) {}
    return {};
  }

  function formatScanDateDisplay(isoDate, lastScanAt) {
    if (!isoDate && !lastScanAt) return "";
    var isPt = lang() === "pt";
    if (lastScanAt) {
      var d = new Date(lastScanAt);
      if (!isNaN(d.getTime())) {
        var dd = pad(d.getDate());
        var mm = pad(d.getMonth() + 1);
        var yyyy = d.getFullYear();
        var hh = pad(d.getHours());
        var mi = pad(d.getMinutes());
        return isPt ? dd + "/" + mm + "/" + yyyy + " " + hh + ":" + mi : yyyy + "-" + mm + "-" + dd + " " + hh + ":" + mi;
      }
    }
    if (isoDate && /^\d{4}-\d{2}-\d{2}$/.test(isoDate)) {
      var pts = isoDate.split("-");
      return isPt ? pts[2] + "/" + pts[1] + "/" + pts[0] : isoDate;
    }
    return isoDate || lastScanAt || "";
  }

  function syncAppToServer(appRec) {
    if (!appRec || !appRec.org || !appRec.assessor) return Promise.resolve(appRec);
    return fetch("/api/applications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(appRec),
    })
      .then(function (r) {
        return r.ok ? r.json() : null;
      })
      .then(function (data) {
        if (data && data.application) return data.application;
        return appRec;
      })
      .catch(function () {
        return appRec;
      });
  }

  function fetchAppsFromServer() {
    return fetch("/api/applications", { cache: "no-store" })
      .then(function (r) {
        return r.ok ? r.json() : null;
      })
      .then(function (data) {
        if (!data || !Array.isArray(data.applications)) return;
        if (data.applications.length > 0) {
          // Merge server apps with local list (server authoritative for matching IDs, keep local-only if any)
          var byId = {};
          data.applications.forEach(function (sa) {
            byId[sa.id] = sa;
          });
          apps.forEach(function (la) {
            if (!byId[la.id]) {
              byId[la.id] = la;
              syncAppToServer(la);
            }
          });
          apps = Object.keys(byId).map(function (k) {
            return byId[k];
          });
          saveAppsLocal();
        } else if (apps.length > 0) {
          apps.forEach(function (la) {
            syncAppToServer(la);
          });
        }
        renderAppsList();
        if (activeAppId) {
          var refreshed = getAppById(activeAppId);
          if (refreshed) {
            state.meta.org = refreshed.org;
            state.meta.assessor = refreshed.assessor;
            state.meta.target = refreshed.target;
            state.meta.date = refreshed.date || state.meta.date || "";
            state.meta.lastScanAt = refreshed.lastScanAt || state.meta.lastScanAt || "";
            syncReadonlySetup();
          }
        }
      })
      .catch(function () {});
  }

  function lang() {
    return state.meta && state.meta.lang === "en" ? "en" : "pt";
  }

  function t() {
    return I18N[lang()];
  }

  function domainLabel(d) {
    if (lang() === "pt" && DATA.domains_pt && DATA.domains_pt[d]) {
      return DATA.domains_pt[d];
    }
    return d;
  }

  function controlTitle(c) {
    return lang() === "pt" && c.title_pt ? c.title_pt : c.title;
  }

  function controlPass(c) {
    return lang() === "pt" && c.pass_criteria_pt ? c.pass_criteria_pt : c.pass_criteria;
  }

  function controlFail(c) {
    return lang() === "pt" && c.fail_criteria_pt ? c.fail_criteria_pt : c.fail_criteria;
  }

  function controlEvidence(c) {
    return lang() === "pt" && c.evidence_items_pt && c.evidence_items_pt.length
      ? c.evidence_items_pt
      : c.evidence_items || [];
  }

  function controlProcedure(c) {
    return lang() === "pt" && c.procedure_items_pt && c.procedure_items_pt.length
      ? c.procedure_items_pt
      : c.procedure_items || [];
  }

  function controlChecklist(c) {
    return lang() === "pt" && c.verification_checklist_pt && c.verification_checklist_pt.length
      ? c.verification_checklist_pt
      : c.verification_checklist || [];
  }

  var saveTimer = null;
  function save() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      try {
        localStorage.setItem(LANG_STORE_KEY, lang());
        if (activeAppId) {
          localStorage.setItem(APP_STATE_PREFIX + activeAppId, JSON.stringify({ answers: state.answers }));
          var curApp = getAppById(activeAppId);
          if (curApp) {
            curApp.targetUrl = state.meta.targetUrl;
            curApp.repoPath = state.meta.repoPath;
            curApp.surfaces = (state.meta.surfaces || ["Web_Application"]).slice();
            curApp.date = state.meta.date || "";
            curApp.lastScanAt = state.meta.lastScanAt || "";
            saveAppsLocal();
          }
        }
      } catch (e) {}
    }, 120);
  }

  function today() {
    var d = new Date();
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
  }
  function pad(n) {
    return (n < 10 ? "0" : "") + n;
  }

  function answer(id) {
    if (!state.answers[id]) {
      state.answers[id] = {
        verdict: null,
        notes: "",
        evidence: {},
        autoLog: "",
        autoTool: "",
        autoTimestamp: "",
        figures: [],
      };
    }
    return state.answers[id];
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function shortDomain(d) {
    return SHORT_DOMAIN[d] || d;
  }

  function shortHash(str) {
    var h1 = 0x811c9dc5 >>> 0;
    for (var i = 0; i < str.length; i++) {
      h1 ^= str.charCodeAt(i);
      h1 = Math.imul(h1, 0x01000193) >>> 0;
    }
    var h2 = (0x9e3779b1 ^ str.length) >>> 0;
    for (var j = 0; j < str.length; j++) {
      h2 = Math.imul((h2 ^ str.charCodeAt(j)) >>> 0, 0x85ebca77) >>> 0;
    }
    return (h1.toString(36) + h2.toString(36)).slice(0, 9);
  }

  function currentReportId() {
    return shortHash(JSON.stringify(state));
  }

  /* ---------- scoping helpers ---------- */
  function isControlInAssuranceLevel(c) {
    var target = state.meta.target || "AL2";
    if (target === "AL1") {
      return c.tier === "AL1";
    }
    return true;
  }

  function isControlMatchingFilter(c) {
    if (!isControlInAssuranceLevel(c)) return false;
    if (activeFilter === "AL1") return c.tier === "AL1";
    if (activeFilter === "AL2") return c.tier === "AL2";
    if (activeFilter === "FAIL") {
      var a = state.answers[c.id];
      return a && (a.verdict === "FAIL" || a.verdict === "Not_Covered");
    }
    return true;
  }

  function isSurfaceApplicable(c) {
    var declared = state.meta.surfaces || ["Web_Application"];
    if (!c.profiles || !c.profiles.length || c.profiles.indexOf("All") !== -1) {
      return true;
    }
    return c.profiles.some(function (p) {
      return declared.indexOf(p) !== -1;
    });
  }

  function applySurfaceScoping() {
    DATA.controls.forEach(function (c) {
      var a = answer(c.id);
      var applicable = isSurfaceApplicable(c);
      if (!applicable && (a.verdict == null || a.autoTool === "surface-scoping")) {
        a.verdict = "NOT_APPLICABLE";
        a.autoTool = "surface-scoping";
        a.autoLog =
          "Marked NOT_APPLICABLE automatically: control applies to [" +
          c.profile +
          "], which is not in declared surfaces [" +
          (state.meta.surfaces || []).join(", ") +
          "].";
      } else if (applicable && a.verdict === "NOT_APPLICABLE" && a.autoTool === "surface-scoping") {
        a.verdict = null;
        a.autoTool = "";
        a.autoLog = "";
      }
    });
    save();
  }

  /* ---------- IndexedDB for Evidence Screenshots ---------- */
  var DB_NAME = "casa3-figures",
    STORE = "img";
  function idb() {
    return new Promise(function (res, rej) {
      if (!("indexedDB" in window)) {
        rej(new Error("no indexedDB"));
        return;
      }
      var r = indexedDB.open(DB_NAME, 1);
      r.onupgradeneeded = function () {
        r.result.createObjectStore(STORE);
      };
      r.onsuccess = function () {
        res(r.result);
      };
      r.onerror = function () {
        rej(r.error);
      };
    });
  }
  function idbPut(id, val) {
    return idb().then(function (db) {
      return new Promise(function (res, rej) {
        var t = db.transaction(STORE, "readwrite");
        t.objectStore(STORE).put(val, id);
        t.oncomplete = function () {
          res();
        };
        t.onerror = function () {
          rej(t.error);
        };
      });
    });
  }
  function idbGet(id) {
    return idb()
      .then(function (db) {
        return new Promise(function (res, rej) {
          var t = db.transaction(STORE, "readonly");
          var rq = t.objectStore(STORE).get(id);
          rq.onsuccess = function () {
            res(rq.result || null);
          };
          rq.onerror = function () {
            rej(rq.error);
          };
        });
      })
      .catch(function () {
        return null;
      });
  }
  function idbDel(id) {
    return idb()
      .then(function (db) {
        return new Promise(function (res) {
          var t = db.transaction(STORE, "readwrite");
          t.objectStore(STORE).delete(id);
          t.oncomplete = function () {
            res();
          };
        });
      })
      .catch(function () {});
  }
  function idbClear() {
    return idb()
      .then(function (db) {
        return new Promise(function (res) {
          var t = db.transaction(STORE, "readwrite");
          t.objectStore(STORE).clear();
          t.oncomplete = function () {
            res();
          };
        });
      })
      .catch(function () {});
  }
  function figId() {
    try {
      if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    } catch (e) {}
    return "f" + Date.now() + "-" + Math.floor(Math.random() * 1e6);
  }
  function readAndResize(file, maxSide) {
    return new Promise(function (res, rej) {
      var fr = new FileReader();
      fr.onload = function () {
        var img = new Image();
        img.onload = function () {
          var scale = Math.min(1, maxSide / Math.max(img.width, img.height));
          var cw = Math.max(1, Math.round(img.width * scale));
          var ch = Math.max(1, Math.round(img.height * scale));
          var cv = document.createElement("canvas");
          cv.width = cw;
          cv.height = ch;
          cv.getContext("2d").drawImage(img, 0, 0, cw, ch);
          var keepPng = file.type === "image/png" && cw * ch < 600000;
          res(cv.toDataURL(keepPng ? "image/png" : "image/jpeg", 0.92));
        };
        img.onerror = rej;
        img.src = fr.result;
      };
      fr.onerror = rej;
      fr.readAsDataURL(file);
    });
  }
  function addFigures(id, files) {
    var imgs = (files || []).filter(function (f) {
      return /^image\//.test(f.type);
    });
    if (!imgs.length) return;
    var a = answer(id);
    a.figures = a.figures || [];
    Promise.all(
      imgs.map(function (f) {
        return readAndResize(f, 1600)
          .then(function (durl) {
            var fid = figId();
            return idbPut(fid, durl).then(function () {
              a.figures.push({ id: fid, caption: "", name: f.name });
            });
          })
          .catch(function () {});
      })
    ).then(function () {
      save();
      renderFigures(id);
    });
  }
  function figuresBlock(c) {
    var tr = t();
    var figs = answer(c.id).figures || [];
    var list = figs.length
      ? figs
          .map(function (f) {
            return (
              '<div class="fig">' +
              '<img class="fig-thumb" data-fig-id="' +
              esc(f.id) +
              '" alt="">' +
              '<div class="fig-meta">' +
              '<input class="fig-cap" type="text" data-act="figcap" data-id="' +
              c.id +
              '" data-fig="' +
              esc(f.id) +
              '" placeholder="' +
              esc(tr.figCaptionPh) +
              '" value="' +
              esc(f.caption || "") +
              '">' +
              '<button class="fig-del" type="button" data-act="figdel" data-id="' +
              c.id +
              '" data-fig="' +
              esc(f.id) +
              '">' +
              esc(tr.removeFig) +
              "</button>" +
              "</div></div>"
            );
          })
          .join("")
      : '<p class="fig-empty">' + esc(tr.dragScreenshots) + "</p>";
    return (
      '<div class="fig-head"><span class="evidence-title">' +
      esc(tr.screenshotsTitle) +
      "</span>" +
      '<label class="btn-mini">' +
      esc(tr.addScreenshot) +
      '<input type="file" accept="image/*" multiple data-act="figfile" data-id="' +
      c.id +
      '" hidden></label>' +
      "</div>" +
      '<div class="fig-list">' +
      list +
      "</div>"
    );
  }
  function loadFigureImages(root) {
    if (!root) return;
    root.querySelectorAll("img.fig-thumb[data-fig-id]").forEach(function (img) {
      if (img.getAttribute("data-loaded")) return;
      img.setAttribute("data-loaded", "1");
      idbGet(img.getAttribute("data-fig-id")).then(function (d) {
        if (d) img.src = d;
      });
    });
  }
  function renderFigures(id) {
    var c = DATA.controls.find(function (x) {
      return x.id === id;
    });
    var host = document.querySelector('[data-figs="' + id + '"]');
    if (c && host) {
      host.innerHTML = figuresBlock(c);
      loadFigureImages(host);
    }
  }

  /* ---------- setup fields (locked read-only in Assessment) & static i18n ---------- */
  var els = {
    orgDisplay: document.getElementById("org-display"),
    assessorDisplay: document.getElementById("assessor-display"),
    dateDisplay: document.getElementById("date-display"),
    targetDisplay: document.getElementById("target-display"),
    targetUrl: document.getElementById("target-url"),
    repoPath: document.getElementById("repo-path"),
    levelDesc: document.getElementById("level-desc"),
    autoStatus: document.getElementById("auto-status"),
    tabApps: document.getElementById("i18n-tab-apps"),
    tabAssess: document.getElementById("i18n-tab-assess"),
    tabReport: document.getElementById("i18n-tab-report"),
    appsList: document.getElementById("apps-list"),
    appsGateNotice: document.getElementById("apps-gate-notice"),
    appForm: document.getElementById("app-form"),
    appEditId: document.getElementById("app-edit-id"),
    appOrg: document.getElementById("app-org"),
    appAssessor: document.getElementById("app-assessor"),
    appTarget: document.getElementById("app-target"),
    appUrl: document.getElementById("app-url"),
    appRepo: document.getElementById("app-repo"),
    appFormError: document.getElementById("app-form-error"),
    btnSaveApp: document.getElementById("btn-save-app"),
    btnCancelEditApp: document.getElementById("btn-cancel-edit-app"),
  };

  function syncLevelDesc() {
    var lv = DATA.assurance_levels && DATA.assurance_levels[state.meta.target];
    if (lv && els.levelDesc) {
      els.levelDesc.textContent = lang() === "pt" && lv.description_pt ? lv.description_pt : lv.description;
    }
  }

  function syncReadonlySetup() {
    var tr = t();
    if (els.orgDisplay) els.orgDisplay.textContent = state.meta.org || "—";
    if (els.assessorDisplay) els.assessorDisplay.textContent = state.meta.assessor || "—";
    if (els.dateDisplay) {
      var fmtDate = formatScanDateDisplay(state.meta.date, state.meta.lastScanAt);
      if (fmtDate) {
        els.dateDisplay.textContent = fmtDate;
        els.dateDisplay.classList.remove("is-pending");
      } else {
        els.dateDisplay.textContent = tr.datePendingScan;
        els.dateDisplay.classList.add("is-pending");
      }
    }
    if (els.targetDisplay) {
      els.targetDisplay.textContent = state.meta.target === "AL1" ? tr.optAL1 : tr.optAL2;
    }
    if (els.targetUrl) els.targetUrl.value = state.meta.targetUrl || "";
    if (els.repoPath) els.repoPath.value = state.meta.repoPath || "";
    document.querySelectorAll("[data-surface]").forEach(function (cb) {
      var surf = cb.getAttribute("data-surface");
      cb.checked = (state.meta.surfaces || ["Web_Application"]).indexOf(surf) !== -1;
    });
    syncLevelDesc();
  }

  function syncTabGating() {
    var locked = !activeAppId;
    var tr = t();
    [els.tabAssess, els.tabReport].forEach(function (tab) {
      if (!tab) return;
      tab.disabled = locked;
      tab.setAttribute("aria-disabled", String(locked));
      tab.title = locked ? tr.tabLockedTitle : "";
    });
    var topresetEl = document.getElementById("topreset");
    if (topresetEl) {
      topresetEl.disabled = locked;
      topresetEl.style.opacity = locked ? "0.45" : "";
    }
  }

  function resetAppForm() {
    editingAppId = "";
    if (els.appEditId) els.appEditId.value = "";
    if (els.appOrg) els.appOrg.value = "";
    if (els.appAssessor) els.appAssessor.value = "";
    if (els.appTarget) els.appTarget.value = "AL2";
    if (els.appUrl) els.appUrl.value = "http://localhost:3000";
    if (els.appRepo) els.appRepo.value = "/home/user/felipe/speckit/juice-shop-master";
    document.querySelectorAll("[data-app-surface]").forEach(function (cb) {
      cb.checked = cb.getAttribute("data-app-surface") === "Web_Application";
    });
    if (els.appFormError) {
      els.appFormError.hidden = true;
      els.appFormError.textContent = "";
    }
    if (els.btnCancelEditApp) els.btnCancelEditApp.hidden = true;
    applyAppFormLabels();
  }

  function applyAppFormLabels() {
    var tr = t();
    var titleEl = document.getElementById("i18n-app-form-title");
    if (titleEl) titleEl.textContent = editingAppId ? tr.appFormTitleEdit : tr.appFormTitleNew;
    if (els.btnSaveApp) els.btnSaveApp.textContent = editingAppId ? tr.appBtnSave : tr.appBtnCreate;
    if (els.btnCancelEditApp) els.btnCancelEditApp.textContent = tr.appBtnCancelEdit;
  }

  function startEditApplication(appId) {
    var app = getAppById(appId);
    if (!app) return;
    editingAppId = app.id;
    if (els.appEditId) els.appEditId.value = app.id;
    if (els.appOrg) els.appOrg.value = app.org || "";
    if (els.appAssessor) els.appAssessor.value = app.assessor || "";
    if (els.appTarget) els.appTarget.value = app.target === "AL1" ? "AL1" : "AL2";
    if (els.appUrl) els.appUrl.value = app.targetUrl || "";
    if (els.appRepo) els.appRepo.value = app.repoPath || "";
    var surfs = Array.isArray(app.surfaces) && app.surfaces.length ? app.surfaces : ["Web_Application"];
    document.querySelectorAll("[data-app-surface]").forEach(function (cb) {
      cb.checked = surfs.indexOf(cb.getAttribute("data-app-surface")) !== -1;
    });
    if (els.btnCancelEditApp) els.btnCancelEditApp.hidden = false;
    if (els.appFormError) els.appFormError.hidden = true;
    applyAppFormLabels();
    var card = document.getElementById("app-form-card");
    if (card && card.scrollIntoView) card.scrollIntoView({ behavior: "smooth", block: "start" });
    if (els.appOrg) els.appOrg.focus();
  }

  function deleteApplication(appId) {
    var app = getAppById(appId);
    if (!app) return;
    if (!confirm(t().appConfirmDelete(app.org))) return;
    apps = apps.filter(function (a) {
      return a.id !== appId;
    });
    saveAppsLocal();
    try {
      localStorage.removeItem(APP_STATE_PREFIX + appId);
      localStorage.removeItem(APP_HISTORY_PREFIX + appId);
    } catch (e) {}
    fetch("/api/applications?id=" + encodeURIComponent(appId), { method: "DELETE" }).catch(function () {});
    if (editingAppId === appId) resetAppForm();
    if (activeAppId === appId) {
      activeAppId = null;
      appScanHistory = [];
      selectedReportRunId = null;
      try {
        localStorage.removeItem(ACTIVE_APP_KEY);
      } catch (e) {}
      state = createEmptyState();
      syncTabGating();
      syncReadonlySetup();
    }
    renderAppsList();
  }

  function selectApplication(appId, targetView) {
    var app = getAppById(appId);
    if (!app) return;
    activeAppId = app.id;
    try {
      localStorage.setItem(ACTIVE_APP_KEY, activeAppId);
    } catch (e) {}
    state = createEmptyState(app);
    state.answers = loadAppAnswers(app.id);
    appScanHistory = loadAppHistoryLocal(app.id, app, state.answers);
    selectedReportRunId = appScanHistory.length ? appScanHistory[appScanHistory.length - 1].id : null;
    fetchAppHistoryFromServer(app.id);
    if (els.appsGateNotice) els.appsGateNotice.hidden = true;
    syncTabGating();
    syncReadonlySetup();
    applySurfaceScoping();
    renderAppsList();
    renderNav();
    renderControls();
    loadFigureImages(document.getElementById("controls"));
    updateProgress();
    var progPanel = document.getElementById("scan-progress-panel");
    if (progPanel && !scanActive) progPanel.hidden = true;
    if (els.autoStatus && !scanActive) {
      els.autoStatus.textContent = t().statusReady;
    }
    if (targetView) {
      switchView(targetView);
    }
  }

  function renderAppsList() {
    if (!els.appsList) return;
    var tr = t();
    if (!apps.length) {
      els.appsList.innerHTML = '<div class="apps-empty">' + esc(tr.appsEmpty) + "</div>";
      return;
    }
    els.appsList.innerHTML = apps
      .map(function (app) {
        var isSel = app.id === activeAppId;
        var scanStr = formatScanDateDisplay(app.date, app.lastScanAt) || tr.appCardNoScan;
        var surfsStr = (app.surfaces || ["Web_Application"]).join(", ");
        var lvlClass = app.target === "AL1" ? "badge-al1" : "badge-al2";
        return (
          '<div class="app-card' +
          (isSel ? " is-selected" : "") +
          '" data-app-id="' +
          esc(app.id) +
          '">' +
          '<div class="app-card-top">' +
          '<h3 class="app-card-name">' +
          esc(app.org) +
          "</h3>" +
          '<div class="app-card-badges">' +
          '<span class="badge ' +
          lvlClass +
          '">' +
          esc(app.target || "AL2") +
          "</span>" +
          (isSel ? '<span class="badge badge-selected">' + esc(tr.appBadgeSelected) + "</span>" : "") +
          "</div></div>" +
          '<div class="app-card-meta">' +
          "<div><strong>" +
          esc(tr.appCardAssessor) +
          "</strong> " +
          esc(app.assessor || "—") +
          "</div>" +
          "<div><strong>" +
          esc(tr.appCardLastScan) +
          "</strong> <code>" +
          esc(scanStr) +
          "</code></div>" +
          (app.targetUrl
            ? "<div><strong>" + esc(tr.appCardUrl) + "</strong> <code>" + esc(app.targetUrl) + "</code></div>"
            : "") +
          "<div><strong>" +
          esc(tr.appCardSurfaces) +
          "</strong> <code>" +
          esc(surfsStr) +
          "</code></div>" +
          "</div>" +
          '<div class="app-card-actions">' +
          '<button type="button" class="btn-mini-act primary-act" data-app-act="assess" data-app-id="' +
          esc(app.id) +
          '">' +
          esc(tr.appActAssess) +
          "</button>" +
          '<button type="button" class="btn-mini-act" data-app-act="report" data-app-id="' +
          esc(app.id) +
          '">' +
          esc(tr.appActReport) +
          "</button>" +
          '<button type="button" class="btn-mini-act" data-app-act="edit" data-app-id="' +
          esc(app.id) +
          '">' +
          esc(tr.appActEdit) +
          "</button>" +
          '<button type="button" class="btn-mini-act danger-act" data-app-act="delete" data-app-id="' +
          esc(app.id) +
          '">' +
          esc(tr.appActDelete) +
          "</button>" +
          "</div></div>"
        );
      })
      .join("");
  }

  function applyStaticI18n() {
    var tr = t();
    document.documentElement.lang = lang() === "pt" ? "pt-BR" : "en";
    document.querySelectorAll(".lang-switch .lang-btn").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-lang") === lang()));
    });

    var setTxt = function (id, val) {
      var el = document.getElementById(id);
      if (el) el.textContent = val;
    };
    setTxt("i18n-brand-sub", tr.brandSub);
    setTxt("topreset", tr.resetBtn);
    var topresetEl = document.getElementById("topreset");
    if (topresetEl) topresetEl.title = tr.resetTitle;
    setTxt("i18n-tab-apps", tr.tabApps);
    setTxt("i18n-tab-assess", tr.tabAssess);
    setTxt("i18n-tab-report", tr.tabReport);

    setTxt("i18n-apps-kicker", tr.appsKicker);
    setTxt("i18n-apps-title", tr.appsTitle);
    var appsLedeEl = document.getElementById("i18n-apps-lede");
    if (appsLedeEl) appsLedeEl.innerHTML = tr.appsLede;
    setTxt("i18n-apps-list-title", tr.appsListTitle);
    setTxt("i18n-apps-list-sub", tr.appsListSub);
    setTxt("btn-focus-new-app", tr.btnFocusNewApp);
    setTxt("i18n-app-form-sub", tr.appFormSub);
    setTxt("i18n-app-lbl-org", tr.appLblOrg);
    setTxt("i18n-app-lbl-assessor", tr.appLblAssessor);
    setTxt("i18n-app-lbl-target", tr.appLblTarget);
    setTxt("i18n-app-opt-al1", tr.optAL1);
    setTxt("i18n-app-opt-al2", tr.optAL2);
    setTxt("i18n-app-lbl-url", tr.lblUrl);
    setTxt("i18n-app-lbl-repo", tr.lblRepo);
    setTxt("i18n-app-surfaces-lbl", tr.surfacesLbl);
    if (els.appOrg) els.appOrg.placeholder = tr.phOrg;
    if (els.appAssessor) els.appAssessor.placeholder = tr.phAssessor;
    applyAppFormLabels();

    setTxt("i18n-hero-kicker", tr.heroKicker);
    setTxt("i18n-hero-title", tr.heroTitle);
    var ledeEl = document.getElementById("i18n-hero-lede");
    if (ledeEl) ledeEl.innerHTML = tr.heroLede;

    setTxt("i18n-lbl-org", tr.lblOrg);
    setTxt("i18n-lbl-assessor", tr.lblAssessor);
    setTxt("i18n-lbl-date", tr.lblDate);
    setTxt("i18n-lbl-target", tr.lblTarget);
    setTxt("i18n-setup-lock-hint", tr.setupLockHint);
    setTxt("btn-manage-apps", tr.btnManageApps);

    setTxt("i18n-pill-auto", tr.pillAuto);
    setTxt("i18n-auto-title", tr.autoTitle);
    setTxt("i18n-surfaces-lbl", tr.surfacesLbl);
    setTxt("i18n-lbl-url", tr.lblUrl);
    setTxt("i18n-lbl-repo", tr.lblRepo);
    setTxt("btn-run-auto", scanActive ? tr.btnRunAutoBusy : tr.btnRunAuto);
    if (lastScanProgress) {
      renderScanProgress(lastScanProgress, scanActive ? "running" : lastScanMode);
    }

    setTxt("i18n-flt-all", tr.fltAll);
    setTxt("i18n-flt-al1", tr.fltAL1);
    setTxt("i18n-flt-al2", tr.fltAL2);
    setTxt("i18n-flt-fail", tr.fltFail);

    setTxt("reset", tr.resetAllBtn);
    setTxt("goto-report", tr.gotoReportBtn);
    setTxt("i18n-foot-txt", tr.footTxt);
    setTxt("i18n-foot-link", tr.footLink);

    syncTabGating();
    syncReadonlySetup();
    renderAppsList();
  }

  /* Language switcher event */
  document.querySelectorAll(".lang-switch .lang-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var selected = btn.getAttribute("data-lang");
      if (selected !== "pt" && selected !== "en") return;
      state.meta.lang = selected;
      try {
        localStorage.setItem(LANG_STORE_KEY, selected);
      } catch (e) {}
      save();
      applyStaticI18n();
      renderNav();
      renderControls();
      loadFigureImages(document.getElementById("controls"));
      updateProgress();
      var reportSec = document.getElementById("view-report");
      if (reportSec && !reportSec.hidden) {
        buildReport();
      }
    });
  });

  if (els.appsList) {
    els.appsList.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-app-act]");
      if (!btn) return;
      var act = btn.getAttribute("data-app-act");
      var aid = btn.getAttribute("data-app-id");
      if (act === "assess") selectApplication(aid, "assess");
      else if (act === "report") selectApplication(aid, "report");
      else if (act === "edit") startEditApplication(aid);
      else if (act === "delete") deleteApplication(aid);
    });
  }

  var btnFocusNewApp = document.getElementById("btn-focus-new-app");
  if (btnFocusNewApp) {
    btnFocusNewApp.addEventListener("click", function () {
      resetAppForm();
      var card = document.getElementById("app-form-card");
      if (card && card.scrollIntoView) card.scrollIntoView({ behavior: "smooth", block: "start" });
      if (els.appOrg) els.appOrg.focus();
    });
  }

  if (els.btnCancelEditApp) {
    els.btnCancelEditApp.addEventListener("click", function () {
      resetAppForm();
    });
  }

  var btnManageApps = document.getElementById("btn-manage-apps");
  if (btnManageApps) {
    btnManageApps.addEventListener("click", function () {
      switchView("apps");
    });
  }

  if (els.appForm) {
    els.appForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var tr = t();
      var orgVal = (els.appOrg ? els.appOrg.value : "").trim();
      var assessorVal = (els.appAssessor ? els.appAssessor.value : "").trim();
      var targetVal = els.appTarget && els.appTarget.value === "AL1" ? "AL1" : "AL2";
      var urlVal = (els.appUrl ? els.appUrl.value : "").trim();
      var repoVal = (els.appRepo ? els.appRepo.value : "").trim();
      var surfs = [];
      document.querySelectorAll("[data-app-surface]").forEach(function (cb) {
        if (cb.checked) surfs.push(cb.getAttribute("data-app-surface"));
      });
      if (!surfs.length) surfs = ["Web_Application"];

      if (!orgVal) {
        if (els.appFormError) {
          els.appFormError.textContent = tr.appErrOrg;
          els.appFormError.hidden = false;
        }
        if (els.appOrg) els.appOrg.focus();
        return;
      }
      if (!assessorVal) {
        if (els.appFormError) {
          els.appFormError.textContent = tr.appErrAssessor;
          els.appFormError.hidden = false;
        }
        if (els.appAssessor) els.appAssessor.focus();
        return;
      }
      if (els.appFormError) els.appFormError.hidden = true;

      var existing = editingAppId ? getAppById(editingAppId) : null;
      var rec = existing
        ? {
            id: existing.id,
            org: orgVal,
            assessor: assessorVal,
            target: targetVal,
            targetUrl: urlVal,
            repoPath: repoVal,
            surfaces: surfs,
            date: existing.date || "",
            lastScanAt: existing.lastScanAt || "",
          }
        : {
            id: "app-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 6),
            org: orgVal,
            assessor: assessorVal,
            target: targetVal,
            targetUrl: urlVal,
            repoPath: repoVal,
            surfaces: surfs,
            date: "",
            lastScanAt: "",
          };

      if (existing) {
        for (var i = 0; i < apps.length; i++) {
          if (apps[i].id === existing.id) {
            apps[i] = rec;
            break;
          }
        }
      } else {
        apps.push(rec);
      }
      saveAppsLocal();
      syncAppToServer(rec);
      resetAppForm();
      if (els.appsGateNotice) els.appsGateNotice.hidden = true;
      selectApplication(rec.id, null);
    });
  }

  document.querySelectorAll("[data-surface]").forEach(function (cb) {
    var surf = cb.getAttribute("data-surface");
    cb.checked = (state.meta.surfaces || ["Web_Application"]).indexOf(surf) !== -1;
    cb.addEventListener("change", function () {
      var checked = [];
      document.querySelectorAll("[data-surface]").forEach(function (el) {
        if (el.checked) checked.push(el.getAttribute("data-surface"));
      });
      state.meta.surfaces = checked.length ? checked : ["Web_Application"];
      applySurfaceScoping();
      renderControls();
      loadFigureImages(document.getElementById("controls"));
      updateProgress();
      var curApp = getAppById(activeAppId);
      if (curApp) {
        curApp.surfaces = state.meta.surfaces.slice();
        saveAppsLocal();
        syncAppToServer(curApp);
      }
    });
  });

  els.targetUrl.addEventListener("input", function () {
    state.meta.targetUrl = els.targetUrl.value;
    save();
  });
  els.repoPath.addEventListener("input", function () {
    state.meta.repoPath = els.repoPath.value;
    save();
  });

  /* Filter pills */
  document.querySelectorAll(".fpill").forEach(function (btn) {
    btn.addEventListener("click", function () {
      activeFilter = btn.getAttribute("data-filter");
      document.querySelectorAll(".fpill").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      renderNav();
      renderControls();
      loadFigureImages(document.getElementById("controls"));
    });
  });

  /* ---------- render controls grouped by domain ---------- */
  function byDomain() {
    var groups = {};
    DATA.domains.forEach(function (d) {
      groups[d] = [];
    });
    DATA.controls.forEach(function (c) {
      if (!isControlMatchingFilter(c)) return;
      (groups[c.domain] = groups[c.domain] || []).push(c);
    });
    return groups;
  }

  function domainId(d) {
    return "domain-" + d.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  }

  function renderNav() {
    var tr = t();
    var groups = byDomain();
    var items = DATA.domains
      .map(function (d) {
        return {
          d: domainLabel(d),
          short: shortDomain(d),
          id: domainId(d),
          n: (groups[d] || []).length,
        };
      })
      .filter(function (it) {
        return it.n > 0;
      });

    document.getElementById("phase-nav").innerHTML = items
      .map(function (it) {
        return (
          '<a href="#' +
          it.id +
          '" data-target="' +
          it.id +
          '">' +
          esc(it.short) +
          " &middot; " +
          esc(it.d) +
          '<span class="n">' +
          it.n +
          "</span></a>"
        );
      })
      .join("");

    var rail = document.getElementById("rail");
    if (rail) {
      rail.innerHTML =
        '<div class="rail-title">' +
        esc(tr.railTitle) +
        "</div><ol>" +
        items
          .map(function (it) {
            return (
              '<li><a href="#' +
              it.id +
              '" data-target="' +
              it.id +
              '" title="' +
              esc(it.d) +
              '">' +
              '<span class="rl">' +
              esc(it.short) +
              " &middot; " +
              esc(it.d) +
              '</span><span class="c">' +
              it.n +
              "</span></a></li>"
            );
          })
          .join("") +
        "</ol>";
    }
  }

  function setActive(id) {
    document.querySelectorAll("[data-target]").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("data-target") === id);
    });
  }

  function setupSpy() {
    var sections = Array.prototype.slice.call(document.querySelectorAll(".phase"));
    if (!sections.length || !("IntersectionObserver" in window)) return;
    var obs = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (en) {
          if (en.isIntersecting) setActive(en.target.id);
        });
      },
      { rootMargin: "-150px 0px -65% 0px", threshold: 0 }
    );
    sections.forEach(function (s) {
      obs.observe(s);
    });
  }

  function verdictSeg(c) {
    var a = answer(c.id);
    var vList = t().verdicts;
    var opts = vList
      .map(function (v) {
        var pressed = a.verdict === v.key;
        var vAttr = v.key == null ? "null" : v.key;
        return (
          '<button type="button" data-act="verdict" data-id="' +
          c.id +
          '" data-verdict="' +
          vAttr +
          '" aria-pressed="' +
          pressed +
          '">' +
          '<span class="lvl">' +
          esc(v.code) +
          '</span><span class="lbl">' +
          esc(v.label) +
          "</span></button>"
        );
      })
      .join("");
    return '<div class="level-seg">' + opts + "</div>";
  }

  function controlDetail(c) {
    var tr = t();
    var a = answer(c.id);

    /* AL1 Automated Control Detail */
    if (c.tier === "AL1") {
      if (a.verdict == null && !a.autoLog) return "";
      var logBlock = a.autoLog
        ? '<div class="auto-log-head"><span>' +
          esc(tr.autoLogHead) +
          " (" +
          esc(a.autoTool || "Scanner") +
          ")</span><span>" +
          esc(a.autoTimestamp || "") +
          '</span></div><div class="auto-log-box">' +
          esc(a.autoLog) +
          "</div>"
        : "";
      return (
        '<div class="level-detail">' +
        logBlock +
        '<div class="notes"><label>' +
        esc(tr.triageNotesLbl) +
        "</label>" +
        '<textarea data-act="notes" data-id="' +
        c.id +
        '" placeholder="' +
        esc(tr.triageNotesPh) +
        '">' +
        esc(a.notes || "") +
        "</textarea></div>" +
        "</div>"
      );
    }

    /* AL2 Lab-Adjudicated Control Detail */
    var checklist = controlChecklist(c);
    var ev = checklist
      .map(function (item, idx) {
        var key = "al2:" + idx;
        var on = a.evidence && a.evidence[key];
        return (
          '<li><input type="checkbox" data-act="ev" data-id="' +
          c.id +
          '" data-key="' +
          key +
          '"' +
          (on ? " checked" : "") +
          " /><span>" +
          esc(item) +
          "</span></li>"
        );
      })
      .join("");
    var evBlock = ev
      ? '<p class="evidence-title">' +
        esc(tr.verifEvidence) +
        '</p><ul class="evidence-list">' +
        ev +
        "</ul>"
      : "";

    return (
      '<div class="level-detail">' +
      evBlock +
      '<div class="notes"><label>' +
      esc(tr.notesLbl) +
      "</label>" +
      '<textarea data-act="notes" data-id="' +
      c.id +
      '" placeholder="' +
      esc(tr.notesPh) +
      '">' +
      esc(a.notes || "") +
      "</textarea></div>" +
      "</div>"
    );
  }

  function controlCard(c) {
    var tr = t();
    var isAL2 = c.tier === "AL2";
    var tierBadge = isAL2
      ? '<span class="badge badge-al2">' + esc(tr.badgeAL2) + "</span>"
      : '<span class="badge badge-al1">' + esc(tr.badgeAL1) + "</span>";
    var profBadge = '<span class="badge badge-prof">' + esc(c.profile) + "</span>";

    var toolsHtml =
      c.reference_tooling && c.reference_tooling.length
        ? '<div class="tooling-row"><span class="tooling-label">' +
          esc(tr.refTooling) +
          "</span>" +
          c.reference_tooling
            .map(function (tl) {
              return '<span class="tool-chip">' + esc(tl) + "</span>";
            })
            .join("") +
          "</div>"
        : "";

    var procHtml = controlProcedure(c)
      .map(function (p) {
        return '<div class="proc-block"><b>' + esc(tr.testProc) + "</b> " + esc(p) + "</div>";
      })
      .join("");

    var evFormatHtml = controlEvidence(c)
      .map(function (e) {
        return '<div class="proc-block"><b>' + esc(tr.reqEvidence) + "</b> " + esc(e) + "</div>";
      })
      .join("");

    var figuresSection = isAL2
      ? '<div class="figures" data-figs="' + c.id + '">' + figuresBlock(c) + "</div>"
      : "";

    return (
      '<div class="control card tier-' +
      c.tier +
      '" id="ctl-' +
      c.id +
      '">' +
      '<div class="control-top">' +
      "<div>" +
      '<div class="control-id-row">' +
      '<span class="control-id">' +
      esc(c.code) +
      "</span>" +
      '<span class="control-ref">' +
      esc(c.reference) +
      "</span>" +
      "</div>" +
      "<h3>" +
      esc(controlTitle(c)) +
      "</h3>" +
      "</div>" +
      '<div class="badge-cluster">' +
      tierBadge +
      profBadge +
      "</div>" +
      "</div>" +
      toolsHtml +
      '<details class="disclose"><summary data-closed-label="' +
      esc(tr.specClosed) +
      '" data-open-label="' +
      esc(tr.specOpen) +
      '"></summary><div class="body">' +
      '<div class="crit-grid">' +
      '<div class="crit-box crit-pass"><b>' +
      esc(tr.passSignal) +
      "</b>" +
      esc(controlPass(c)) +
      "</div>" +
      '<div class="crit-box crit-fail"><b>' +
      esc(tr.failSignal) +
      "</b>" +
      esc(controlFail(c)) +
      "</div>" +
      "</div>" +
      evFormatHtml +
      procHtml +
      "</div></details>" +
      '<div class="levels" data-levels="' +
      c.id +
      '">' +
      verdictSeg(c) +
      controlDetail(c) +
      "</div>" +
      figuresSection +
      "</div>"
    );
  }

  function renderControls() {
    var tr = t();
    var groups = byDomain();
    var html = DATA.domains
      .map(function (d) {
        var list = groups[d] || [];
        if (!list.length) return "";
        var al1N = list.filter(function (x) {
          return x.tier === "AL1";
        }).length;
        var al2N = list.filter(function (x) {
          return x.tier === "AL2";
        }).length;
        var countLabel = tr.controlsCount(list.length, al1N, al2N);
        return (
          '<section class="phase" id="' +
          domainId(d) +
          '">' +
          '<div class="phase-head"><h2>' +
          esc(domainLabel(d)) +
          '</h2><span class="count">' +
          esc(countLabel) +
          "</span></div>" +
          list.map(controlCard).join("") +
          "</section>"
        );
      })
      .join("");
    document.getElementById("controls").innerHTML =
      html || '<div class="card empty">' + esc(tr.emptyFilter) + "</div>";
    setupSpy();
  }

  function refreshControlLevel(id) {
    var c = DATA.controls.find(function (x) {
      return x.id === id;
    });
    var host = document.querySelector('[data-levels="' + id + '"]');
    if (c && host) host.innerHTML = verdictSeg(c) + controlDetail(c);
  }

  /* ---------- events (delegated) ---------- */
  var controlsEl = document.getElementById("controls");
  controlsEl.addEventListener("click", function (e) {
    var btn = e.target.closest('[data-act="verdict"]');
    if (btn) {
      var id = btn.getAttribute("data-id");
      var v = btn.getAttribute("data-verdict");
      var a = answer(id);
      a.verdict = v === "null" ? null : v;
      if (a.autoTool === "surface-scoping") a.autoTool = "manual-override";
      save();
      refreshControlLevel(id);
      updateProgress();
      return;
    }
    var fd = e.target.closest('[data-act="figdel"]');
    if (fd) {
      var cid = fd.getAttribute("data-id"),
        fid = fd.getAttribute("data-fig");
      var ans = answer(cid);
      ans.figures = (ans.figures || []).filter(function (x) {
        return x.id !== fid;
      });
      idbDel(fid);
      save();
      renderFigures(cid);
    }
  });

  controlsEl.addEventListener("change", function (e) {
    var ev = e.target.closest('[data-act="ev"]');
    if (ev) {
      var a = answer(ev.getAttribute("data-id"));
      a.evidence = a.evidence || {};
      a.evidence[ev.getAttribute("data-key")] = ev.checked;
      save();
      return;
    }
    var ff = e.target.closest('[data-act="figfile"]');
    if (ff) {
      addFigures(ff.getAttribute("data-id"), Array.prototype.slice.call(ff.files || []));
      ff.value = "";
    }
  });

  controlsEl.addEventListener("input", function (e) {
    var nt = e.target.closest('[data-act="notes"]');
    if (nt) {
      answer(nt.getAttribute("data-id")).notes = nt.value;
      save();
      return;
    }
    var fc = e.target.closest('[data-act="figcap"]');
    if (fc) {
      var fid = fc.getAttribute("data-fig");
      (answer(fc.getAttribute("data-id")).figures || []).forEach(function (x) {
        if (x.id === fid) x.caption = fc.value;
      });
      save();
    }
  });

  controlsEl.addEventListener("dragover", function (e) {
    if (e.target.closest(".figures")) {
      e.preventDefault();
    }
  });
  controlsEl.addEventListener("drop", function (e) {
    var fz = e.target.closest(".figures");
    if (fz) {
      e.preventDefault();
      addFigures(fz.getAttribute("data-figs"), Array.prototype.slice.call(e.dataTransfer.files || []));
    }
  });

  /* ---------- progress ---------- */
  function updateProgress() {
    var tr = t();
    var inScope = DATA.controls.filter(isControlInAssuranceLevel);
    var done = inScope.filter(function (c) {
      var a = state.answers[c.id];
      return a && a.verdict != null;
    });
    var al1All = inScope.filter(function (c) {
      return c.tier === "AL1";
    });
    var al1Done = al1All.filter(function (c) {
      var a = state.answers[c.id];
      return a && a.verdict != null;
    });
    var al2All = inScope.filter(function (c) {
      return c.tier === "AL2";
    });
    var al2Done = al2All.filter(function (c) {
      var a = state.answers[c.id];
      return a && a.verdict != null;
    });

    var total = inScope.length;
    var pct = total ? Math.round((done.length / total) * 100) : 0;
    document.getElementById("progress-count").textContent = tr.progressCount(
      done.length,
      total,
      state.meta.target || "AL2"
    );
    document.getElementById("progress-breakdown").textContent = tr.progressBreakdown(
      al1Done.length,
      al1All.length,
      al2Done.length,
      al2All.length
    );
    document.getElementById("progress-pct").textContent = pct + "%";
    document.getElementById("progress-fill").style.width = pct + "%";
  }

  /* ---------- Automated AL1 Scanner & Evidence Importer ---------- */
  function applyScanResults(resultsMap, sourceLabel) {
    var now = new Date();
    var ts = now.toISOString().replace("T", " ").slice(0, 19) + " UTC";
    var isoDate = today();
    var isoFull = now.toISOString();
    var updated = 0;
    Object.keys(resultsMap).forEach(function (cid) {
      var r = resultsMap[cid];
      var a = answer(cid);
      a.verdict = r.verdict;
      a.autoTool = r.tool || sourceLabel || "casa-auto-engine";
      a.autoLog = r.log || "";
      a.autoTimestamp = ts;
      updated++;
    });
    // SDD 194: Automatically populate Evaluation Date upon scan completion
    state.meta.date = isoDate;
    state.meta.lastScanAt = isoFull;
    var curApp = getAppById(activeAppId);
    if (curApp) {
      curApp.date = isoDate;
      curApp.lastScanAt = isoFull;
      saveAppsLocal();
      syncAppToServer(curApp);
    }
    syncReadonlySetup();
    recordScanRunSnapshot(sourceLabel, now);
    renderAppsList();
    save();
    renderControls();
    loadFigureImages(controlsEl);
    updateProgress();
    if (els.autoStatus) {
      els.autoStatus.textContent =
        (lang() === "pt" ? "Concluído (" : "Completed (") +
        sourceLabel +
        "): " +
        updated +
        (lang() === "pt" ? " controles AL1 avaliados em " : " AL1 controls evaluated at ") +
        ts;
    }
  }

  /* 1. Live Scan via Async Progress API (/api/scan/start + /api/scan/status) with /api/scan fallback */
  var SCAN_DOMAINS = [
    ["SCA", 5],
    ["SAST", 13],
    ["TLS", 6],
    ["CFG", 11],
    ["AUT", 8],
    ["AZI", 6],
    ["OAU", 9],
    ["WHK", 3],
  ];
  var scanActive = false;
  var scanPollTimer = null;
  var scanClockTimer = null;
  var scanStartMs = 0;
  var lastScanProgress = null;
  var lastScanMode = "running";

  function formatScanElapsed(totalSec) {
    var s = Math.max(0, Math.floor(totalSec || 0));
    var mm = String(Math.floor(s / 60)).padStart(2, "0");
    var ss = String(s % 60).padStart(2, "0");
    return mm + ":" + ss;
  }

  function buildInitialScanProgress() {
    var doms = {};
    SCAN_DOMAINS.forEach(function (pair) {
      doms[pair[0]] = { done: 0, total: pair[1], status: "pending", pass: 0, fail: 0 };
    });
    return {
      completed: 0,
      total: 61,
      percent: 0,
      elapsed_sec: 0,
      current_domain: "SCA",
      stage_pt: "Iniciando scan automatizado AL1 (61 controles em 8 domínios)…",
      stage_en: "Starting automated AL1 scan (61 controls across 8 domains)…",
      last_control: "",
      last_verdict: "",
      last_tool: "",
      counts: { PASS: 0, FAIL: 0, NOT_APPLICABLE: 0, Not_Covered: 0 },
      domains: doms,
      domain_order: SCAN_DOMAINS.map(function (p) { return p[0]; }),
    };
  }

  function renderScanProgress(prog, mode) {
    if (!prog) return;
    lastScanProgress = prog;
    lastScanMode = mode || "running";

    var panel = document.getElementById("scan-progress-panel");
    if (!panel) return;
    panel.hidden = false;
    panel.classList.remove("is-running", "is-completed", "is-error");
    panel.classList.add("is-" + lastScanMode);

    var tr = t();
    var stageEl = document.getElementById("scan-prog-stage");
    var countEl = document.getElementById("scan-prog-count");
    var pctEl = document.getElementById("scan-prog-pct");
    var elapsedEl = document.getElementById("scan-prog-elapsed");
    var barEl = document.getElementById("scan-prog-bar");
    var fillEl = document.getElementById("scan-prog-fill");
    var gridEl = document.getElementById("scan-domain-grid");
    var tallyEl = document.getElementById("scan-prog-tally");
    var lastEl = document.getElementById("scan-prog-last");

    var stageTxt = lang() === "pt" ? (prog.stage_pt || tr.statusRunning) : (prog.stage_en || tr.statusRunning);
    var completed = typeof prog.completed === "number" ? prog.completed : 0;
    var total = typeof prog.total === "number" && prog.total > 0 ? prog.total : 61;
    var pct = typeof prog.percent === "number" ? prog.percent : Math.round((completed / total) * 100);
    var elapsedVal = lastScanMode === "running" && scanStartMs
      ? Math.max(prog.elapsed_sec || 0, (Date.now() - scanStartMs) / 1000)
      : (prog.elapsed_sec || 0);

    if (stageEl) stageEl.textContent = stageTxt;
    if (countEl) countEl.textContent = completed + "/" + total;
    if (pctEl) pctEl.textContent = pct + "%";
    if (elapsedEl) elapsedEl.textContent = formatScanElapsed(elapsedVal);
    if (barEl) barEl.setAttribute("aria-valuenow", String(pct));
    if (fillEl) fillEl.style.width = Math.max(lastScanMode === "running" ? 2 : 0, Math.min(100, pct)) + "%";

    if (els.autoStatus && lastScanMode === "running") {
      els.autoStatus.textContent =
        (lang() === "pt" ? "Progresso: " : "Progress: ") +
        completed + "/" + total + " (" + pct + "%) · " +
        (prog.current_domain || "SCA") + " · " + formatScanElapsed(elapsedVal);
    }

    if (gridEl) {
      var domOrder = prog.domain_order || SCAN_DOMAINS.map(function (p) { return p[0]; });
      var domMap = prog.domains || {};
      gridEl.innerHTML = domOrder.map(function (dom) {
        var info = domMap[dom] || { done: 0, total: 0, status: "pending" };
        var st = info.status || "pending";
        var mark = st === "done" ? " ✓" : (st === "running" ? " ●" : "");
        return (
          '<div class="scan-dom-chip is-' + esc(st) + '">' +
          '<span class="dom-code">' + esc(dom) + mark + "</span>" +
          '<span class="dom-cnt">' + esc(String(info.done || 0)) + "/" + esc(String(info.total || 0)) + "</span>" +
          "</div>"
        );
      }).join("");
    }

    if (tallyEl) {
      var c = prog.counts || {};
      tallyEl.innerHTML =
        '<span class="tally-pill tally-pass">PASS ' + (c.PASS || 0) + "</span>" +
        '<span class="tally-pill tally-fail">FAIL ' + (c.FAIL || 0) + "</span>" +
        '<span class="tally-pill tally-na">N/A ' + (c.NOT_APPLICABLE || 0) + "</span>" +
        '<span class="tally-pill tally-nc">N/C ' + (c.Not_Covered || 0) + "</span>";
    }

    if (lastEl) {
      if (prog.last_control) {
        lastEl.textContent =
          tr.scanLastPrefix + " " + prog.last_control +
          (prog.last_verdict ? " [" + prog.last_verdict + "]" : "") +
          (prog.last_tool ? " — " + prog.last_tool : "");
      } else {
        lastEl.textContent = tr.scanWaitingCtrl;
      }
    }
  }

  function stopScanTimers() {
    if (scanPollTimer) {
      clearTimeout(scanPollTimer);
      scanPollTimer = null;
    }
    if (scanClockTimer) {
      clearInterval(scanClockTimer);
      scanClockTimer = null;
    }
  }

  function finishScanUI(btn, mode, prog) {
    stopScanTimers();
    scanActive = false;
    if (btn) {
      btn.disabled = false;
      btn.textContent = t().btnRunAuto;
    }
    if (prog) {
      renderScanProgress(prog, mode);
    }
  }

  function runLegacySyncScan(btn, payload) {
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        var doneProg = lastScanProgress || buildInitialScanProgress();
        doneProg.completed = (data && data.count) || 61;
        doneProg.percent = 100;
        doneProg.elapsed_sec = (Date.now() - scanStartMs) / 1000;
        doneProg.stage_pt = "Scan concluído — " + doneProg.completed + " controles AL1 avaliados.";
        doneProg.stage_en = "Scan completed — " + doneProg.completed + " AL1 controls evaluated.";
        finishScanUI(btn, "completed", doneProg);
        if (data && data.results) {
          applyScanResults(data.results, "ada-casa-audit Live Scanner");
        }
      })
      .catch(function () {
        var errProg = lastScanProgress || buildInitialScanProgress();
        errProg.elapsed_sec = (Date.now() - scanStartMs) / 1000;
        errProg.stage_pt = "Erro: Servidor local (/api/scan) inacessível. Inicie python3 -m casa_audit.";
        errProg.stage_en = "Error: Local scanner server (/api/scan) unreachable. Start python3 -m casa_audit.";
        finishScanUI(btn, "error", errProg);
        runClientSideAutomatedScan();
      });
  }

  document.getElementById("btn-run-auto").addEventListener("click", function () {
    if (scanActive) return;
    var btn = document.getElementById("btn-run-auto");
    scanActive = true;
    scanStartMs = Date.now();
    btn.disabled = true;
    btn.textContent = t().btnRunAutoBusy;

    var payload = {
      target_url: state.meta.targetUrl || "",
      repo_path: state.meta.repoPath || "",
      surfaces: state.meta.surfaces || ["Web_Application"],
    };

    renderScanProgress(buildInitialScanProgress(), "running");
    stopScanTimers();
    scanClockTimer = setInterval(function () {
      if (scanActive && lastScanProgress) {
        var elapsedEl = document.getElementById("scan-prog-elapsed");
        if (elapsedEl) {
          elapsedEl.textContent = formatScanElapsed((Date.now() - scanStartMs) / 1000);
        }
      }
    }, 1000);

    function pollStatus(scanId) {
      if (!scanActive) return;
      fetch("/api/scan/status?id=" + encodeURIComponent(scanId), { cache: "no-store" })
        .then(function (res) {
          if (!res.ok) throw new Error("HTTP " + res.status);
          return res.json();
        })
        .then(function (snap) {
          if (snap && snap.progress) {
            renderScanProgress(snap.progress, snap.status === "completed" ? "completed" : (snap.status === "error" ? "error" : "running"));
          }
          if (snap.status === "completed") {
            finishScanUI(btn, "completed", snap.progress);
            if (snap.results) {
              applyScanResults(snap.results, "ada-casa-audit Live Scanner");
            }
          } else if (snap.status === "error") {
            finishScanUI(btn, "error", snap.progress);
            if (els.autoStatus) {
              els.autoStatus.textContent = t().scanErrorPrefix + " " + (snap.error || "Unknown error");
            }
          } else {
            scanPollTimer = setTimeout(function () { pollStatus(scanId); }, 600);
          }
        })
        .catch(function (err) {
          var errProg = lastScanProgress || buildInitialScanProgress();
          errProg.elapsed_sec = (Date.now() - scanStartMs) / 1000;
          errProg.stage_pt = t().scanErrorPrefix + " " + (err && err.message ? err.message : "Falha ao consultar status.");
          errProg.stage_en = t().scanErrorPrefix + " " + (err && err.message ? err.message : "Failed to poll status.");
          finishScanUI(btn, "error", errProg);
          runClientSideAutomatedScan();
        });
    }

    fetch("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then(function (res) {
        if (res.status === 404) {
          runLegacySyncScan(btn, payload);
          return null;
        }
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (started) {
        if (!started) return;
        if (started.progress) {
          renderScanProgress(started.progress, "running");
        }
        if (started.scan_id) {
          scanPollTimer = setTimeout(function () { pollStatus(started.scan_id); }, 400);
        } else {
          runLegacySyncScan(btn, payload);
        }
      })
      .catch(function () {
        var errProg = lastScanProgress || buildInitialScanProgress();
        errProg.elapsed_sec = (Date.now() - scanStartMs) / 1000;
        errProg.stage_pt = "Erro: Servidor local (/api/scan) inacessível. Inicie python3 -m casa_audit.";
        errProg.stage_en = "Error: Local scanner server (/api/scan) unreachable. Start python3 -m casa_audit.";
        finishScanUI(btn, "error", errProg);
        runClientSideAutomatedScan();
      });
  });

  function runClientSideAutomatedScan() {
    if (els.autoStatus) {
      els.autoStatus.textContent =
        lang() === "pt"
          ? "Erro: Servidor local (/api/scan) inacessível. Inicie python3 -m casa_audit."
          : "Error: Local scanner server (/api/scan) unreachable. Start python3 -m casa_audit.";
    }
  }

  /* ---------- SVG Charts & Pipeline for Report ---------- */
  function donut(frac, label, sub) {
    var r = 54,
      c = 2 * Math.PI * r;
    frac = Math.max(0, Math.min(1, frac || 0));
    var off = c * (1 - frac);
    return (
      '<svg viewBox="0 0 140 140" class="donut" role="img" aria-label="Compliance rate ' +
      esc(label) +
      '">' +
      '<circle class="d-track" cx="70" cy="70" r="' +
      r +
      '"/>' +
      '<circle class="d-val" cx="70" cy="70" r="' +
      r +
      '" stroke-dasharray="' +
      c.toFixed(2) +
      '" stroke-dashoffset="' +
      off.toFixed(2) +
      '" transform="rotate(-90 70 70)"/>' +
      '<text class="d-num" x="70" y="72" text-anchor="middle">' +
      esc(label) +
      "</text>" +
      '<text class="d-sub" x="70" y="90" text-anchor="middle">' +
      esc(sub) +
      "</text>" +
      "</svg>"
    );
  }

  function radarChart(rows) {
    var N = rows.length,
      cx = 200,
      cy = 162,
      R = 112;
    if (!N) return "";
    function pt(i, rad) {
      var ang = ((-90 + (i * 360) / N) * Math.PI) / 180;
      return [cx + rad * Math.cos(ang), cy + rad * Math.sin(ang)];
    }
    function poly(rad, cls) {
      var pts = [];
      for (var i = 0; i < N; i++) {
        var p = pt(i, rad(i));
        pts.push(p[0].toFixed(1) + "," + p[1].toFixed(1));
      }
      return '<polygon class="' + cls + '" points="' + pts.join(" ") + '"/>';
    }
    var rings = [0.33, 0.66, 1]
      .map(function (rv) {
        return poly(function () {
          return rv * R;
        }, "ring");
      })
      .join("");
    var axes = "",
      labels = "",
      dots = "";
    for (var i = 0; i < N; i++) {
      var e = pt(i, R);
      axes +=
        '<line class="axis" x1="' +
        cx +
        '" y1="' +
        cy +
        '" x2="' +
        e[0].toFixed(1) +
        '" y2="' +
        e[1].toFixed(1) +
        '"/>';
      var lp = pt(i, R + 22);
      var anchor = Math.abs(lp[0] - cx) < 12 ? "middle" : lp[0] > cx ? "start" : "end";
      labels +=
        '<text class="r-label" x="' +
        lp[0].toFixed(1) +
        '" y="' +
        (lp[1] + 4).toFixed(1) +
        '" text-anchor="' +
        anchor +
        '">' +
        esc(shortDomain(rows[i].domain)) +
        "</text>";
      var v = rows[i].rate == null ? 0 : rows[i].rate;
      var dp = pt(i, v * R);
      dots += '<circle class="r-dot" cx="' + dp[0].toFixed(1) + '" cy="' + dp[1].toFixed(1) + '" r="2.8"/>';
    }
    var data = poly(function (i) {
      var v = rows[i].rate == null ? 0 : rows[i].rate;
      return v * R;
    }, "r-data");
    return (
      '<svg viewBox="0 0 400 330" class="radar" role="img" aria-label="Compliance by domain">' +
      rings +
      axes +
      data +
      dots +
      labels +
      "</svg>"
    );
  }

  function lerpShade(tVal) {
    tVal = Math.max(0, Math.min(1, tVal));
    var a = [228, 228, 233],
      b = [29, 29, 31];
    var r = Math.round(a[0] + (b[0] - a[0]) * tVal);
    var g = Math.round(a[1] + (b[1] - a[1]) * tVal);
    var bl = Math.round(a[2] + (b[2] - a[2]) * tVal);
    return "rgb(" + r + "," + g + "," + bl + ")";
  }

  function domainPipeline(rows) {
    var tr = t();
    var stages = rows
      .map(function (r, i) {
        var has = r.rate != null;
        var tVal = has ? r.rate : 0;
        var bg = has ? lerpShade(tVal) : "var(--bg-subtle)";
        var col = has ? (tVal > 0.55 ? "#fff" : "var(--text)") : "var(--text-3)";
        var arrow = i < rows.length - 1 ? '<div class="pl-arrow" aria-hidden="true">&rsaquo;</div>' : "";
        var pctTxt = has ? Math.round(r.rate * 100) + "%" : "&ndash;";
        return (
          '<div class="pl-stage" style="background:' +
          bg +
          ";color:" +
          col +
          '" title="' +
          esc(domainLabel(r.domain)) +
          (has ? " - " + Math.round(r.rate * 100) + "% PASS" : "") +
          '">' +
          '<div class="pl-name">' +
          esc(shortDomain(r.domain)) +
          "</div>" +
          '<div class="pl-val">' +
          pctTxt +
          "</div>" +
          "</div>" +
          arrow
        );
      })
      .join("");
    return (
      '<div class="section-title">' +
      esc(tr.secPipeline) +
      "</div>" +
      '<div class="pipeline card">' +
      '<div class="pl-row">' +
      stages +
      "</div>" +
      '<div class="pl-cap">' +
      esc(tr.pipelineCap) +
      "</div>" +
      "</div>"
    );
  }

  function passRateEvolutionChart(runs, selectedId) {
    var tr = t();
    var isPt = lang() === "pt";
    if (!runs || !runs.length) {
      return (
        '<div class="section-title">' +
        esc(tr.secEvolution) +
        "</div>" +
        '<div class="evolution-card card"><div class="evo-head"><h3 class="evo-title">' +
        esc(tr.evoTitle) +
        '</h3><div class="evo-meta">' +
        esc(tr.evoRunsCount(0)) +
        '</div></div><div class="evo-cap">' +
        esc(tr.evoEmpty) +
        "</div></div>"
      );
    }

    var ptsData = runs.map(function (r, idx) {
      var sum = r.summary && typeof r.summary.passPct === "number"
        ? r.summary
        : computeAnswersSummary(r.answers || {}, r.target || state.meta.target);
      return {
        id: r.id,
        idx: idx + 1,
        pct: Math.max(0, Math.min(100, Math.round(sum.passPct || 0))),
        passed: sum.passedCount || 0,
        applicable: sum.applicableCount || 0,
        failed: (sum.failCount || 0) + (sum.notCoveredCount || 0),
        shortDate: formatShortChartDate(r.date, r.executedAt),
        fullDate: formatScanDateDisplay(r.date, r.executedAt) || r.date || "—",
        selected: r.id === selectedId,
      };
    });

    var W = 820,
      H = 225,
      padL = 46,
      padR = 28,
      padT = 26,
      padB = 42,
      plotW = W - padL - padR,
      plotH = H - padT - padB;

    function xFor(i) {
      if (ptsData.length === 1) return padL + plotW / 2;
      return padL + (i / (ptsData.length - 1)) * plotW;
    }
    function yFor(pct) {
      return padT + (1 - pct / 100) * plotH;
    }

    var gridHtml = [0, 25, 50, 75, 100]
      .map(function (v) {
        var y = yFor(v).toFixed(1);
        return (
          '<line class="evo-grid" x1="' +
          padL +
          '" y1="' +
          y +
          '" x2="' +
          (W - padR) +
          '" y2="' +
          y +
          '"/>' +
          '<text class="evo-axis-lbl" x="' +
          (padL - 8) +
          '" y="' +
          (Number(y) + 4).toFixed(1) +
          '" text-anchor="end">' +
          v +
          "%</text>"
        );
      })
      .join("");

    var coords = ptsData.map(function (p, i) {
      return { x: xFor(i), y: yFor(p.pct), data: p };
    });

    var lineSvg = "";
    var areaSvg = "";
    if (coords.length >= 2) {
      var polyPts = coords
        .map(function (c) {
          return c.x.toFixed(1) + "," + c.y.toFixed(1);
        })
        .join(" ");
      var baseY = yFor(0).toFixed(1);
      var areaPts =
        coords[0].x.toFixed(1) +
        "," +
        baseY +
        " " +
        polyPts +
        " " +
        coords[coords.length - 1].x.toFixed(1) +
        "," +
        baseY;
      areaSvg = '<polygon class="evo-area" points="' + areaPts + '"/>';
      lineSvg = '<polyline class="evo-line" points="' + polyPts + '"/>';
    }

    // Thin X-axis labels cleanly if many runs exist
    var labelStep = coords.length > 10 ? Math.ceil(coords.length / 8) : 1;
    var pointsSvg = coords
      .map(function (c, i) {
        var p = c.data;
        var showDate = i === 0 || i === coords.length - 1 || i % labelStep === 0 || p.selected;
        var tip =
          "#" +
          p.idx +
          " · " +
          p.fullDate +
          " · " +
          p.pct +
          "% PASS (" +
          p.passed +
          "/" +
          p.applicable +
          (isPt ? " aplicáveis, " : " applicable, ") +
          p.failed +
          " FAIL/NC)";
        return (
          '<g class="evo-point' +
          (p.selected ? " is-selected" : "") +
          '" data-run-id="' +
          esc(p.id) +
          '" tabindex="0" role="button" aria-label="' +
          esc(tip) +
          '">' +
          "<title>" +
          esc(tip) +
          "</title>" +
          (p.selected ? '<circle class="evo-ring" cx="' + c.x.toFixed(1) + '" cy="' + c.y.toFixed(1) + '" r="8"/>' : "") +
          '<circle class="evo-dot" cx="' +
          c.x.toFixed(1) +
          '" cy="' +
          c.y.toFixed(1) +
          '" r="' +
          (p.selected ? "6" : "4.5") +
          '"/>' +
          '<text class="evo-val-lbl" x="' +
          c.x.toFixed(1) +
          '" y="' +
          (c.y - 11).toFixed(1) +
          '" text-anchor="middle">' +
          p.pct +
          "%</text>" +
          (showDate
            ? '<text class="evo-date-lbl" x="' +
              c.x.toFixed(1) +
              '" y="' +
              (H - 12).toFixed(1) +
              '" text-anchor="middle">' +
              esc(p.shortDate) +
              "</text>"
            : "") +
          "</g>"
        );
      })
      .join("");

    // Compute delta badge comparing selected run (or latest) vs previous run
    var deltaHtml = "";
    var selIdx = ptsData.findIndex(function (p) {
      return p.selected;
    });
    if (selIdx < 0) selIdx = ptsData.length - 1;
    if (selIdx > 0) {
      var diff = ptsData[selIdx].pct - ptsData[selIdx - 1].pct;
      var cls = diff > 0 ? "is-up" : diff < 0 ? "is-down" : "is-flat";
      var sign = diff > 0 ? "+" + diff + "% ↑" : diff < 0 ? diff + "% ↓" : "0% =";
      deltaHtml = '<span class="evo-delta ' + cls + '">' + sign + "</span>";
    }

    return (
      '<div class="section-title">' +
      esc(tr.secEvolution) +
      "</div>" +
      '<div class="evolution-card card">' +
      '<div class="evo-head">' +
      '<h3 class="evo-title">' +
      esc(tr.evoTitle) +
      "</h3>" +
      '<div class="evo-meta">' +
      deltaHtml +
      "<span>" +
      esc(tr.evoRunsCount(ptsData.length)) +
      "</span></div></div>" +
      '<svg viewBox="0 0 ' +
      W +
      " " +
      H +
      '" class="evo-svg" role="img" aria-label="' +
      esc(tr.evoTitle) +
      '">' +
      gridHtml +
      areaSvg +
      lineSvg +
      pointsSvg +
      "</svg>" +
      '<div class="evo-cap">' +
      esc(ptsData.length === 1 ? tr.evoSingleHint : tr.evoMultiHint) +
      "</div></div>"
    );
  }

  function getActiveReportRun() {
    if (!appScanHistory.length) return null;
    if (selectedReportRunId) {
      for (var i = 0; i < appScanHistory.length; i++) {
        if (appScanHistory[i].id === selectedReportRunId) return appScanHistory[i];
      }
    }
    return appScanHistory[appScanHistory.length - 1];
  }

  /* ---------- Report View (Latest scan by default + Historical selector & Pass Evolution — SDD 195) ---------- */
  function buildReport() {
    var tr = t();
    var isPt = lang() === "pt";
    var runs = appScanHistory.slice();
    var activeRun = getActiveReportRun();
    var latestRun = runs.length ? runs[runs.length - 1] : null;
    var activeIdx = activeRun
      ? runs.findIndex(function (r) {
          return r.id === activeRun.id;
        })
      : -1;
    var isViewingHistorical = Boolean(activeRun && latestRun && activeRun.id !== latestRun.id);

    var reportAnswers = activeRun ? (activeRun.answers || {}) : state.answers;
    var target = (activeRun && activeRun.target) || state.meta.target || "AL2";
    var reportSurfaces = (activeRun && activeRun.surfaces) || state.meta.surfaces || ["Web_Application"];
    var reportDateRaw = activeRun ? activeRun.date : state.meta.date;
    var reportExecAt = activeRun ? activeRun.executedAt : state.meta.lastScanAt;

    var inScope = DATA.controls.filter(function (c) {
      return target === "AL1" ? c.tier === "AL1" : true;
    });
    var assessed = inScope.filter(function (c) {
      var a = reportAnswers[c.id];
      return a && a.verdict != null;
    });
    var applicableAssessed = assessed.filter(function (c) {
      return reportAnswers[c.id].verdict !== "NOT_APPLICABLE";
    });
    var passed = applicableAssessed.filter(function (c) {
      return reportAnswers[c.id].verdict === "PASS";
    });
    var failed = applicableAssessed.filter(function (c) {
      var v = reportAnswers[c.id].verdict;
      return v === "FAIL" || v === "Not_Covered";
    });

    var passRate = applicableAssessed.length ? passed.length / applicableAssessed.length : 0;

    var al1InScope = inScope.filter(function (c) {
      return c.tier === "AL1";
    });
    var al1Passed = al1InScope.filter(function (c) {
      var a = reportAnswers[c.id];
      return a && (a.verdict === "PASS" || a.verdict === "NOT_APPLICABLE");
    });

    var al2InScope = inScope.filter(function (c) {
      return c.tier === "AL2";
    });
    var al2Passed = al2InScope.filter(function (c) {
      var a = reportAnswers[c.id];
      return a && (a.verdict === "PASS" || a.verdict === "NOT_APPLICABLE");
    });

    var domainRows = DATA.domains.map(function (d) {
      var dControls = inScope.filter(function (c) {
        return c.domain === d;
      });
      var dEval = dControls.filter(function (c) {
        var a = reportAnswers[c.id];
        return a && a.verdict != null && a.verdict !== "NOT_APPLICABLE";
      });
      var dPass = dEval.filter(function (c) {
        return reportAnswers[c.id].verdict === "PASS";
      });
      var rate = dEval.length ? dPass.length / dEval.length : null;
      return { domain: d, rate: rate, passed: dPass.length, evalCount: dEval.length, total: dControls.length };
    });

    var figNum = 0,
      figuresOrder = [],
      figByControl = {};
    inScope.forEach(function (c) {
      var a = reportAnswers[c.id];
      if (!a || !a.figures || !a.figures.length) return;
      a.figures.forEach(function (f) {
        figNum++;
        figuresOrder.push({
          num: figNum,
          controlId: c.id,
          code: c.code,
          title: controlTitle(c),
          figId: f.id,
          caption: f.caption || "",
        });
        (figByControl[c.id] = figByControl[c.id] || []).push(figNum);
      });
    });

    var certBadge = '<span class="cert-badge cert-inc">' + esc(tr.certInc) + "</span>";
    if (assessed.length === inScope.length && failed.length === 0) {
      certBadge = '<span class="cert-badge cert-pass">' + esc(tr.certPass(target)) + "</span>";
    } else if (failed.length > 0) {
      certBadge = '<span class="cert-badge cert-fail">' + esc(tr.certFail(failed.length)) + "</span>";
    }

    var who = state.meta.org ? esc(state.meta.org) : isPt ? "A aplicação alvo" : "The target application";
    var formattedEvalDate = formatScanDateDisplay(reportDateRaw, reportExecAt);
    var when = formattedEvalDate ? (isPt ? " em " : " on ") + esc(formattedEvalDate) : "";
    var introBody = isPt
      ? "<p><b>" +
        who +
        "</b> foi avaliada contra a <b>Especificação App Defense Alliance CASA 3.0 (" +
        esc(target) +
        ")</b>" +
        when +
        ". " +
        assessed.length +
        " de " +
        inScope.length +
        " controles em escopo foram avaliados nas superfícies declaradas (<code>" +
        esc(reportSurfaces.join(", ")) +
        "</code>), alcançando uma taxa de conformidade de <b>" +
        Math.round(passRate * 100) +
        "%</b>.</p>" +
        "<p>Segundo as regras do CASA 3.0, todos os 61 controles do AL1 são decididos de forma determinística a partir das saídas das ferramentas automatizadas (SARIF 2.1.0, SBOM CycloneDX, W3C HAR 1.2), enquanto os 15 controles do AL2 incorporam checklists de evidências de verificação adjudicadas pelo laboratório, notas e capturas de tela. Qualquer veredito <code>FAIL</code> ou <code>Not_Covered</code> bloqueia a certificação até ser corrigido e reverificado.</p>"
      : "<p><b>" +
        who +
        "</b> was evaluated against the <b>App Defense Alliance CASA 3.0 Specification (" +
        esc(target) +
        ")</b>" +
        when +
        ". " +
        assessed.length +
        " of " +
        inScope.length +
        " in-scope controls were evaluated across declared surfaces (<code>" +
        esc(reportSurfaces.join(", ")) +
        "</code>), achieving a compliance pass rate of <b>" +
        Math.round(passRate * 100) +
        "%</b>.</p>" +
        "<p>Under CASA 3.0 rules, every AL1 control is decided deterministically from automated tool output (SARIF 2.1.0, CycloneDX SBOM, W3C HAR 1.2), while AL2 controls incorporate lab-adjudicated verification evidence checklists, notes, and screenshots. Any <code>FAIL</code> or unexcused <code>Not_Covered</code> verdict blocks certification until remediated and re-verified.</p>";

    if (figNum) {
      introBody += isPt
        ? "<p>" +
          figNum +
          " captura" +
          (figNum > 1 ? "s de tela estão anexadas" : " de tela está anexada") +
          " como evidência complementar do AL2 (Figura" +
          (figNum > 1 ? "s 1–" + figNum : " 1") +
          ").</p>"
        : "<p>" +
          figNum +
          " screenshot" +
          (figNum > 1 ? "s are" : " is") +
          " attached as supporting AL2 lab evidence (Figure" +
          (figNum > 1 ? "s 1–" + figNum : " 1") +
          ").</p>";
    }

    var meta = state.meta;
    var reportId = currentReportId();
    var metaLine =
      (meta.org ? "<span>" + esc(meta.org) + "</span>" : "") +
      (meta.assessor ? "<span>" + esc(meta.assessor) + "</span>" : "") +
      "<span>" +
      esc(formattedEvalDate || tr.reportNoScanDate) +
      "</span>" +
      "<span>" +
      (isPt ? "Alvo " : "Target ") +
      esc(target) +
      "</span>" +
      '<span class="rid">Report #' +
      reportId +
      "</span>";

    var stats =
      '<div class="stat-grid">' +
      '<div class="stat card"><div class="num">' +
      assessed.length +
      "/" +
      inScope.length +
      '</div><div class="lab">' +
      esc(tr.statEval) +
      "</div></div>" +
      '<div class="stat card"><div class="num">' +
      Math.round(passRate * 100) +
      '%</div><div class="lab">' +
      esc(tr.statPassRate) +
      "</div></div>" +
      '<div class="stat card"><div class="num">' +
      al1Passed.length +
      "/" +
      al1InScope.length +
      '</div><div class="lab">' +
      esc(tr.statAL1) +
      "</div></div>" +
      '<div class="stat card"><div class="num">' +
      (al2InScope.length ? al2Passed.length + "/" + al2InScope.length : "N/A") +
      '</div><div class="lab">' +
      esc(tr.statAL2) +
      "</div></div>" +
      "</div>";

    var charts =
      '<div class="section-title">' +
      esc(tr.secOverview) +
      "</div>" +
      '<div class="charts card">' +
      '<div class="donut-wrap">' +
      donut(passRate, Math.round(passRate * 100) + "%", "PASS RATE") +
      '<div class="donut-cap">' +
      esc(tr.donutCap) +
      "</div></div>" +
      '<div class="radar-wrap">' +
      radarChart(domainRows) +
      "</div>" +
      "</div>";

    var pipeline = domainPipeline(domainRows);

    var gapHtml;
    if (!assessed.length) {
      gapHtml = '<div class="card empty">' + esc(tr.emptyReportNoEval) + "</div>";
    } else if (!failed.length) {
      gapHtml = '<div class="card empty">' + esc(tr.emptyReportAllPass(target)) + "</div>";
    } else {
      gapHtml = failed
        .map(function (c) {
          var a = reportAnswers[c.id];
          var figs = figByControl[c.id];
          var figWord = isPt ? "Figura " : "Figure ";
          var figRef = figs
            ? '<div class="gap-figref">' +
              esc(tr.suppEvidence) +
              " " +
              figs
                .map(function (n) {
                  return figWord + n;
                })
                .join(", ") +
              "</div>"
            : "";
          var logSnippet = a.autoLog
            ? '<div class="auto-log-box" style="margin-top:10px">' + esc(a.autoLog) + "</div>"
            : "";
          var note = a.notes
            ? '<div class="gap-note"><b>' + esc(tr.assessorNote) + "</b> " + esc(a.notes) + "</div>"
            : "";
          var tools = (c.reference_tooling || []).join(", ");

          return (
            '<div class="gap card">' +
            '<div class="gap-top"><div>' +
            '<span class="g-id">' +
            esc(c.code) +
            " &middot; " +
            esc(c.tier) +
            " &middot; " +
            esc(c.reference) +
            "</span>" +
            '<div class="g-title">' +
            esc(controlTitle(c)) +
            "</div></div>" +
            '<div class="gap-move">Verdict: ' +
            esc(a.verdict) +
            "</div></div>" +
            '<div class="gap-next">' +
            '<p class="nl">' +
            esc(tr.reqPassToFix) +
            "</p>" +
            '<p class="nd">' +
            esc(controlPass(c)) +
            "</p>" +
            (tools
              ? '<p class="nd"><b>' + esc(tr.refTooling) + "</b> <code>" + esc(tools) + "</code></p>"
              : "") +
            "</div>" +
            logSnippet +
            note +
            figRef +
            "</div>"
          );
        })
        .join("");
    }

    var historyOptions = runs.length
      ? runs
          .slice()
          .reverse()
          .map(function (r, revIdx) {
            var num = runs.length - revIdx;
            var sum = r.summary && typeof r.summary.passPct === "number"
              ? r.summary
              : computeAnswersSummary(r.answers || {}, r.target || target);
            var dt = formatScanDateDisplay(r.date, r.executedAt) || r.date || "—";
            var latestSuffix = revIdx === 0 ? " (" + tr.repHistLatestTag + ")" : "";
            var optLabel = "#" + num + " — " + dt + " · " + sum.passPct + "% PASS" + latestSuffix;
            return (
              '<option value="' +
              esc(r.id) +
              '"' +
              (activeRun && activeRun.id === r.id ? " selected" : "") +
              ">" +
              esc(optLabel) +
              "</option>"
            );
          })
          .join("")
      : '<option value="">' + esc(tr.repHistNoRuns) + "</option>";

    var historyBar =
      '<div class="report-history-bar card">' +
      '<div class="rh-left">' +
      '<label class="rh-label" for="report-run-select">' +
      esc(tr.repHistLabel) +
      "</label>" +
      '<select id="report-run-select" class="rh-select"' +
      (!runs.length ? " disabled" : "") +
      ">" +
      historyOptions +
      "</select></div>" +
      '<div class="rh-actions">' +
      '<button type="button" class="rh-btn" id="btn-run-prev"' +
      (activeIdx <= 0 ? " disabled" : "") +
      ">" +
      esc(tr.repHistPrev) +
      "</button>" +
      '<button type="button" class="rh-btn" id="btn-run-next"' +
      (activeIdx < 0 || activeIdx >= runs.length - 1 ? " disabled" : "") +
      ">" +
      esc(tr.repHistNext) +
      "</button>" +
      (isViewingHistorical
        ? '<button type="button" class="rh-btn is-primary" id="btn-run-latest">' + esc(tr.repHistGoLatest) + "</button>"
        : "") +
      "</div></div>";

    var historicalBanner = isViewingHistorical
      ? '<div class="history-banner" role="status"><span>' +
        esc(tr.repHistBanner(activeIdx + 1, runs.length, formattedEvalDate || reportDateRaw || "—")) +
        '</span><button type="button" class="rh-btn is-primary" id="btn-banner-latest">' +
        esc(tr.repHistGoLatest) +
        "</button></div>"
      : "";

    var evolutionBlock = passRateEvolutionChart(runs, activeRun ? activeRun.id : null);

    var notAssessed = inScope.length - assessed.length;
    var summaryNote =
      '<div class="section-title">' + esc(tr.secFindings(failed.length, notAssessed, figNum)) + "</div>";

    document.getElementById("report").innerHTML =
      historyBar +
      historicalBanner +
      '<div class="report-head"><div><h1>' +
      esc(tr.reportTitle) +
      "</h1>" +
      '<div class="report-meta">' +
      metaLine +
      "</div></div>" +
      certBadge +
      "</div>" +
      '<div class="report-intro">' +
      introBody +
      "</div>" +
      stats +
      evolutionBlock +
      charts +
      pipeline +
      summaryNote +
      gapHtml +
      '<div id="evidence-slot"></div>' +
      '<div class="report-actions">' +
      '<button class="btn ghost" id="back-apps" type="button">' +
      esc(tr.btnBackApps) +
      "</button>" +
      '<button class="btn ghost" id="back" type="button">' +
      esc(tr.btnBack) +
      "</button>" +
      '<button class="btn ghost" id="export" type="button">' +
      esc(tr.btnExport) +
      "</button>" +
      '<button class="btn primary" id="print" type="button">' +
      esc(tr.btnPrint) +
      "</button>" +
      "</div>";

    var runSel = document.getElementById("report-run-select");
    if (runSel) {
      runSel.addEventListener("change", function () {
        selectedReportRunId = runSel.value || null;
        buildReport();
      });
    }
    var btnPrev = document.getElementById("btn-run-prev");
    if (btnPrev && activeIdx > 0) {
      btnPrev.addEventListener("click", function () {
        selectedReportRunId = runs[activeIdx - 1].id;
        buildReport();
      });
    }
    var btnNext = document.getElementById("btn-run-next");
    if (btnNext && activeIdx >= 0 && activeIdx < runs.length - 1) {
      btnNext.addEventListener("click", function () {
        selectedReportRunId = runs[activeIdx + 1].id;
        buildReport();
      });
    }
    ["btn-run-latest", "btn-banner-latest"].forEach(function (bid) {
      var bEl = document.getElementById(bid);
      if (bEl && latestRun) {
        bEl.addEventListener("click", function () {
          selectedReportRunId = latestRun.id;
          buildReport();
        });
      }
    });
    document.querySelectorAll("#report .evo-point[data-run-id]").forEach(function (pt) {
      var jumpToRun = function () {
        var rid = pt.getAttribute("data-run-id");
        if (rid) {
          selectedReportRunId = rid;
          buildReport();
        }
      };
      pt.addEventListener("click", jumpToRun);
      pt.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          jumpToRun();
        }
      });
    });

    document.getElementById("back-apps").addEventListener("click", function () {
      switchView("apps");
    });
    document.getElementById("back").addEventListener("click", function () {
      switchView("assess");
    });
    document.getElementById("print").addEventListener("click", function () {
      var slug =
        (state.meta.org || "app").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "") || "app";
      var prev = document.title;
      document.title = "CASA3-" + target + "-" + slug + "-" + (reportDateRaw || today());
      function restore() {
        document.title = prev;
        window.removeEventListener("afterprint", restore);
      }
      window.addEventListener("afterprint", restore);
      window.print();
    });
    document.getElementById("export").addEventListener("click", exportJson);

    loadEvidence(figuresOrder);
  }

  function loadEvidence(items) {
    var tr = t();
    var isPt = lang() === "pt";
    var slot = document.getElementById("evidence-slot");
    if (!slot) return;
    if (!items || !items.length) {
      slot.innerHTML = "";
      return;
    }
    Promise.all(
      items.map(function (it) {
        return idbGet(it.figId).then(function (d) {
          return {
            num: it.num,
            controlId: it.controlId,
            code: it.code,
            title: it.title,
            caption: it.caption,
            data: d,
          };
        });
      })
    ).then(function (loaded) {
      var order = [],
        groups = {};
      loaded.forEach(function (it) {
        if (!groups[it.controlId]) {
          groups[it.controlId] = { code: it.code, title: it.title, items: [] };
          order.push(it.controlId);
        }
        groups[it.controlId].items.push(it);
      });
      var html = '<div class="section-title">' + esc(tr.secScreenshots) + "</div>";
      order.forEach(function (cid) {
        var g = groups[cid];
        html +=
          '<div class="evidence-block card"><div class="ev-ctl"><b>' +
          esc(g.code) +
          "</b> &mdash; " +
          esc(g.title) +
          "</div>";
        g.items.forEach(function (it) {
          var figLabel = (isPt ? "Figura " : "Figure ") + it.num;
          html +=
            '<figure class="figure">' +
            (it.data
              ? '<img src="' + it.data + '" alt="' + figLabel + '">'
              : '<div class="fig-missing">Image unavailable</div>') +
            "<figcaption><b>" +
            figLabel +
            ".</b> " +
            (it.caption ? esc(it.caption) : '<span class="muted">' + esc(tr.noCaption) + "</span>") +
            "</figcaption></figure>";
        });
        html += "</div>";
      });
      slot.innerHTML = html;
    });
  }

  function exportJson() {
    var activeRun = getActiveReportRun();
    var exportAnswers = activeRun ? (activeRun.answers || {}) : state.answers;
    var exportTarget = (activeRun && activeRun.target) || state.meta.target || "AL2";
    var exportMeta = cloneJson(state.meta);
    if (activeRun) {
      exportMeta.date = activeRun.date || exportMeta.date;
      exportMeta.lastScanAt = activeRun.executedAt || exportMeta.lastScanAt;
      exportMeta.target = exportTarget;
      exportMeta.scanRunId = activeRun.id;
    }
    var id = shortHash(JSON.stringify({ meta: exportMeta, answers: exportAnswers }));
    var inScope = DATA.controls.filter(function (c) {
      return exportTarget === "AL1" ? c.tier === "AL1" : true;
    });
    var payload = {
      standard: DATA.standard,
      version: DATA.version,
      report_id: id,
      exported_at: new Date().toISOString(),
      meta: exportMeta,
      results: inScope.map(function (c) {
        var a = exportAnswers[c.id] || {};
        return {
          id: c.id,
          code: c.code,
          tier: c.tier,
          automation: c.automation,
          domain: c.domain,
          profile: c.profile,
          title: c.title,
          title_pt: c.title_pt || "",
          verdict: a.verdict || null,
          autoTool: a.autoTool || "",
          autoLog: a.autoLog || "",
          evidence_checklist: a.evidence || {},
          notes: a.notes || "",
          screenshots: (a.figures || []).map(function (f) {
            return f.caption || f.name || "screenshot";
          }),
        };
      }),
    };
    var blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var orgslug =
      (state.meta.org || "report").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") ||
      "report";
    var name =
      "casa3-" +
      (state.meta.target || "al2").toLowerCase() +
      "-" +
      orgslug +
      "-" +
      (state.meta.date || today()) +
      "-" +
      id +
      ".json";
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 1000);
  }

  /* ---------- view switching (gated on selected application — SDD 194) ---------- */
  function switchView(view) {
    if ((view === "assess" || view === "report") && !activeAppId) {
      if (els.appsGateNotice) {
        els.appsGateNotice.textContent = t().gateNotice;
        els.appsGateNotice.hidden = false;
      }
      view = "apps";
    }
    currentView = view;
    var appsSec = document.getElementById("view-apps");
    var assess = document.getElementById("view-assess");
    var report = document.getElementById("view-report");
    if (appsSec) appsSec.hidden = view !== "apps";
    if (assess) assess.hidden = view !== "assess";
    if (report) report.hidden = view !== "report";
    document.querySelectorAll(".view-switch .seg").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-view") === view));
    });
    if (view === "apps") renderAppsList();
    if (view === "assess") syncReadonlySetup();
    if (view === "report") {
      // SDD 195: Always open Report showing the latest scan execution by default
      selectedReportRunId = appScanHistory.length ? appScanHistory[appScanHistory.length - 1].id : null;
      buildReport();
      fetchAppHistoryFromServer(activeAppId);
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  document.querySelectorAll(".view-switch .seg").forEach(function (b) {
    b.addEventListener("click", function () {
      switchView(b.getAttribute("data-view"));
    });
  });
  document.getElementById("goto-report").addEventListener("click", function () {
    switchView("report");
  });
  document.getElementById("brand-home").addEventListener("click", function (e) {
    e.preventDefault();
    switchView("apps");
  });

  function resetAll() {
    if (!activeAppId) return;
    var tr = t();
    if (!confirm(tr.confirmReset)) return;
    var currentLang = lang();
    var curApp = getAppById(activeAppId);
    try {
      localStorage.removeItem(APP_STATE_PREFIX + activeAppId);
      localStorage.removeItem(APP_HISTORY_PREFIX + activeAppId);
    } catch (e) {}
    appScanHistory = [];
    selectedReportRunId = null;
    fetch("/api/applications/history?app_id=" + encodeURIComponent(activeAppId), { method: "DELETE" }).catch(function () {});
    idbClear();
    if (curApp) {
      curApp.date = "";
      curApp.lastScanAt = "";
      saveAppsLocal();
      syncAppToServer(curApp);
    }
    state = createEmptyState(curApp);
    state.meta.lang = currentLang;
    applyStaticI18n();
    applySurfaceScoping();
    switchView("assess");
    renderNav();
    renderControls();
    loadFigureImages(controlsEl);
    updateProgress();
    var progPanel = document.getElementById("scan-progress-panel");
    if (progPanel) progPanel.hidden = true;
    if (els.autoStatus) {
      els.autoStatus.textContent = t().statusReady;
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  document.getElementById("reset").addEventListener("click", resetAll);
  var topresetBtn = document.getElementById("topreset");
  if (topresetBtn) topresetBtn.addEventListener("click", resetAll);

  /* ---------- init (always opens on Applications view for pre-selection — SDD 194) ---------- */
  applyStaticI18n();
  switchView("apps");
  fetchAppsFromServer();
})();

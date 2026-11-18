/* ADA CASA 3.0 Assessment Frontend - Vanilla JS, localStorage + IndexedDB + Automated AL1 Engine + PT/EN i18n */
(function () {
  "use strict";

  var DATA = window.CASA3_DATA;
  var STORE_KEY = "casa3-assessment-v1";

  var I18N = {
    pt: {
      brandSub: "Avaliação de Segurança de Aplicações Web",
      resetBtn: "Limpar",
      resetTitle: "Limpar todos os vereditos, execuções, notas e capturas salvas neste navegador",
      tabAssess: "Avaliação",
      tabReport: "Relatório",
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
      statusReady: "Pronto — 61 controles AL1 aguardando execução automatizada.",
      statusRunning: "Executando verificações automatizadas do AL1 (SCA, SAST, TLS, CFG, AUT, AZI, OAU, WHK)…",
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
      resetTitle: "Clear all saved verdicts, automated runs, notes and screenshots stored in this browser",
      tabAssess: "Assessment",
      tabReport: "Report",
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
      statusReady: "Ready — 61 AL1 controls awaiting automated scan.",
      statusRunning: "Running automated AL1 checks (SCA, SAST, TLS, CFG, AUT, AZI, OAU, WHK)…",
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

  /* ---------- state ---------- */
  var state = load();
  var activeFilter = "all";

  function load() {
    try {
      var raw = localStorage.getItem(STORE_KEY);
      if (raw) {
        var parsed = JSON.parse(raw);
        parsed.meta = parsed.meta || {};
        parsed.meta.lang = parsed.meta.lang || "pt";
        parsed.meta.surfaces = parsed.meta.surfaces || ["Web_Application"];
        parsed.answers = parsed.answers || {};
        return parsed;
      }
    } catch (e) {}
    return {
      meta: {
        lang: "pt",
        org: "OWASP Juice Shop",
        assessor: "",
        date: today(),
        target: "AL2",
        targetUrl: "http://localhost:3000",
        repoPath: "/home/user/felipe/speckit/juice-shop-master",
        surfaces: ["Web_Application"],
      },
      answers: {},
    };
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
        localStorage.setItem(STORE_KEY, JSON.stringify(state));
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

  /* ---------- setup fields & static i18n ---------- */
  var els = {
    org: document.getElementById("org"),
    assessor: document.getElementById("assessor"),
    date: document.getElementById("date"),
    target: document.getElementById("target"),
    targetUrl: document.getElementById("target-url"),
    repoPath: document.getElementById("repo-path"),
    levelDesc: document.getElementById("level-desc"),
    autoStatus: document.getElementById("auto-status"),
  };

  els.org.value = state.meta.org || "";
  els.assessor.value = state.meta.assessor || "";
  els.date.value = state.meta.date || today();
  els.target.value = state.meta.target || "AL2";
  els.targetUrl.value = state.meta.targetUrl || "http://localhost:3000";
  els.repoPath.value = state.meta.repoPath || "/home/user/felipe/speckit/juice-shop-master";

  function syncLevelDesc() {
    var lv = DATA.assurance_levels && DATA.assurance_levels[state.meta.target];
    if (lv && els.levelDesc) {
      els.levelDesc.textContent = lang() === "pt" && lv.description_pt ? lv.description_pt : lv.description;
    }
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
    setTxt("i18n-tab-assess", tr.tabAssess);
    setTxt("i18n-tab-report", tr.tabReport);
    setTxt("i18n-hero-kicker", tr.heroKicker);
    setTxt("i18n-hero-title", tr.heroTitle);
    var ledeEl = document.getElementById("i18n-hero-lede");
    if (ledeEl) ledeEl.innerHTML = tr.heroLede;

    setTxt("i18n-lbl-org", tr.lblOrg);
    els.org.placeholder = tr.phOrg;
    setTxt("i18n-lbl-assessor", tr.lblAssessor);
    els.assessor.placeholder = tr.phAssessor;
    setTxt("i18n-lbl-date", tr.lblDate);
    setTxt("i18n-lbl-target", tr.lblTarget);
    setTxt("i18n-opt-al1", tr.optAL1);
    setTxt("i18n-opt-al2", tr.optAL2);

    setTxt("i18n-pill-auto", tr.pillAuto);
    setTxt("i18n-auto-title", tr.autoTitle);
    setTxt("i18n-surfaces-lbl", tr.surfacesLbl);
    setTxt("i18n-lbl-url", tr.lblUrl);
    setTxt("i18n-lbl-repo", tr.lblRepo);
    setTxt("btn-run-auto", tr.btnRunAuto);

    setTxt("i18n-flt-all", tr.fltAll);
    setTxt("i18n-flt-al1", tr.fltAL1);
    setTxt("i18n-flt-al2", tr.fltAL2);
    setTxt("i18n-flt-fail", tr.fltFail);

    setTxt("reset", tr.resetAllBtn);
    setTxt("goto-report", tr.gotoReportBtn);
    setTxt("i18n-foot-txt", tr.footTxt);
    setTxt("i18n-foot-link", tr.footLink);

    syncLevelDesc();
  }

  /* Language switcher event */
  document.querySelectorAll(".lang-switch .lang-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var selected = btn.getAttribute("data-lang");
      if (selected !== "pt" && selected !== "en") return;
      state.meta.lang = selected;
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

  document.querySelectorAll("[data-surface]").forEach(function (cb) {
    var surf = cb.getAttribute("data-surface");
    cb.checked = (state.meta.surfaces || ["Web_Application"]).indexOf(surf) !== -1;
    cb.addEventListener("change", function () {
      var checked = [];
      document.querySelectorAll("[data-surface]").forEach(function (el) {
        if (el.checked) checked.push(el.getAttribute("data-surface"));
      });
      state.meta.surfaces = checked;
      applySurfaceScoping();
      renderControls();
      loadFigureImages(document.getElementById("controls"));
      updateProgress();
    });
  });

  els.org.addEventListener("input", function () {
    state.meta.org = els.org.value;
    save();
  });
  els.assessor.addEventListener("input", function () {
    state.meta.assessor = els.assessor.value;
    save();
  });
  els.date.addEventListener("input", function () {
    state.meta.date = els.date.value;
    save();
  });
  els.targetUrl.addEventListener("input", function () {
    state.meta.targetUrl = els.targetUrl.value;
    save();
  });
  els.repoPath.addEventListener("input", function () {
    state.meta.repoPath = els.repoPath.value;
    save();
  });
  els.target.addEventListener("change", function () {
    state.meta.target = els.target.value;
    syncLevelDesc();
    save();
    renderNav();
    renderControls();
    loadFigureImages(document.getElementById("controls"));
    updateProgress();
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
    var ts = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
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

  /* 1. Live Scan via Backend API (/api/scan) with fallback */
  document.getElementById("btn-run-auto").addEventListener("click", function () {
    var btn = document.getElementById("btn-run-auto");
    btn.disabled = true;
    if (els.autoStatus) {
      els.autoStatus.textContent = t().statusRunning;
    }

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_url: state.meta.targetUrl || "",
        repo_path: state.meta.repoPath || "",
        surfaces: state.meta.surfaces || ["Web_Application"],
      }),
    })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        btn.disabled = false;
        if (data && data.results) {
          applyScanResults(data.results, "ada-casa-audit Live Scanner");
        }
      })
      .catch(function () {
        btn.disabled = false;
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

  /* ---------- Report View ---------- */
  function buildReport() {
    var tr = t();
    var isPt = lang() === "pt";
    var target = state.meta.target || "AL2";
    var inScope = DATA.controls.filter(isControlInAssuranceLevel);
    var assessed = inScope.filter(function (c) {
      var a = state.answers[c.id];
      return a && a.verdict != null;
    });
    var applicableAssessed = assessed.filter(function (c) {
      return state.answers[c.id].verdict !== "NOT_APPLICABLE";
    });
    var passed = applicableAssessed.filter(function (c) {
      return state.answers[c.id].verdict === "PASS";
    });
    var failed = applicableAssessed.filter(function (c) {
      var v = state.answers[c.id].verdict;
      return v === "FAIL" || v === "Not_Covered";
    });

    var passRate = applicableAssessed.length ? passed.length / applicableAssessed.length : 0;

    var al1InScope = inScope.filter(function (c) {
      return c.tier === "AL1";
    });
    var al1Passed = al1InScope.filter(function (c) {
      var a = state.answers[c.id];
      return a && (a.verdict === "PASS" || a.verdict === "NOT_APPLICABLE");
    });

    var al2InScope = inScope.filter(function (c) {
      return c.tier === "AL2";
    });
    var al2Passed = al2InScope.filter(function (c) {
      var a = state.answers[c.id];
      return a && (a.verdict === "PASS" || a.verdict === "NOT_APPLICABLE");
    });

    var domainRows = DATA.domains.map(function (d) {
      var dControls = inScope.filter(function (c) {
        return c.domain === d;
      });
      var dEval = dControls.filter(function (c) {
        var a = state.answers[c.id];
        return a && a.verdict != null && a.verdict !== "NOT_APPLICABLE";
      });
      var dPass = dEval.filter(function (c) {
        return state.answers[c.id].verdict === "PASS";
      });
      var rate = dEval.length ? dPass.length / dEval.length : null;
      return { domain: d, rate: rate, passed: dPass.length, evalCount: dEval.length, total: dControls.length };
    });

    var figNum = 0,
      figuresOrder = [],
      figByControl = {};
    inScope.forEach(function (c) {
      var a = state.answers[c.id];
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
    var when = state.meta.date ? (isPt ? " em " : " on ") + esc(state.meta.date) : "";
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
        esc((state.meta.surfaces || ["Web_Application"]).join(", ")) +
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
        esc((state.meta.surfaces || ["Web_Application"]).join(", ")) +
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
      (meta.date ? "<span>" + esc(meta.date) + "</span>" : "") +
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
          var a = state.answers[c.id];
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

    var notAssessed = inScope.length - assessed.length;
    var summaryNote =
      '<div class="section-title">' + esc(tr.secFindings(failed.length, notAssessed, figNum)) + "</div>";

    document.getElementById("report").innerHTML =
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
      charts +
      pipeline +
      summaryNote +
      gapHtml +
      '<div id="evidence-slot"></div>' +
      '<div class="report-actions">' +
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

    document.getElementById("back").addEventListener("click", function () {
      switchView("assess");
    });
    document.getElementById("print").addEventListener("click", function () {
      var slug =
        (state.meta.org || "app").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "") || "app";
      var prev = document.title;
      document.title = "CASA3-" + (state.meta.target || "AL2") + "-" + slug + "-" + (state.meta.date || today());
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
    var id = currentReportId();
    var inScope = DATA.controls.filter(isControlInAssuranceLevel);
    var payload = {
      standard: DATA.standard,
      version: DATA.version,
      report_id: id,
      exported_at: new Date().toISOString(),
      meta: state.meta,
      results: inScope.map(function (c) {
        var a = state.answers[c.id] || {};
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

  /* ---------- view switching ---------- */
  function switchView(view) {
    var assess = document.getElementById("view-assess");
    var report = document.getElementById("view-report");
    var isReport = view === "report";
    assess.hidden = isReport;
    report.hidden = !isReport;
    document.querySelectorAll(".view-switch .seg").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-view") === view));
    });
    if (isReport) buildReport();
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
    switchView("assess");
  });

  function resetAll() {
    var tr = t();
    if (!confirm(tr.confirmReset)) return;
    var currentLang = lang();
    try {
      localStorage.removeItem(STORE_KEY);
    } catch (e) {}
    idbClear();
    state = load();
    state.meta.lang = currentLang;
    els.org.value = state.meta.org;
    els.assessor.value = "";
    els.date.value = state.meta.date;
    els.target.value = "AL2";
    applyStaticI18n();
    applySurfaceScoping();
    switchView("assess");
    renderNav();
    renderControls();
    loadFigureImages(controlsEl);
    updateProgress();
    if (els.autoStatus) {
      els.autoStatus.textContent = t().statusReady;
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  document.getElementById("reset").addEventListener("click", resetAll);
  var topresetBtn = document.getElementById("topreset");
  if (topresetBtn) topresetBtn.addEventListener("click", resetAll);

  /* ---------- init ---------- */
  applyStaticI18n();
  applySurfaceScoping();
  renderNav();
  renderControls();
  loadFigureImages(controlsEl);
  updateProgress();
})();

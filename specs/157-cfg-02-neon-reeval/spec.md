# SDD 157 — CFG-02 Reavaliação Neon (Debug Modes Disabled)

## Controle Alvo
- **ID:** `CFG-02` (Controle `26/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 576–594)
- **Ferramentas de Referência do Guia:** `Nuclei (exposures/ + misconfiguration/ templates), OWASP ZAP`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza ProjectDiscovery Nuclei 3.11.1 (`rules/nuclei_cfg02`) + OWASP ZAP 2.17.0 (`10023`/`90022`/`40042`). Zero uso de Burp Suite pago.
2. **Lacuna Identificada:** O passo 2 do Test Guide exige inspecionar respostas rastreadas (crawled responses) em busca de marcadores de debug de frameworks (Django `DEBUG = True`, Flask/Werkzeug `EVALEX`, Rails `Action Controller: Exception caught`, ASP.NET `Server Error in '/' Application`, Laravel Whoops/Ignition). `evaluate_cfg02_debug_modes` inspecionava apenas resultados de templates fixos do Nuclei e alertas do ZAP, sem analisar o corpo das respostas `crawled_exchanges`.

## Critérios de Aceitação
- `evaluate_cfg02_debug_modes` aceita `crawled_exchanges: list[dict] | None = None` (e recebe `crawled_exchanges` em `run_dynamic_and_protocol_checks`).
- Detecta marcadores de debug de Django, Werkzeug/Flask, Rails, ASP.NET e Laravel/Whoops em respostas rastreadas como `debug_marker` com achado SARIF `error`.
- Respostas de produção limpas permanecem `PASS`.
- Regressão (`test_iteration96_cfg02_guide_tooling`) e novo teste (`test_iteration157_cfg02_neon_reeval`) passam 100%.

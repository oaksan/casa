# SDD 176 — AZI-02 Reavaliação Neon (Cross-Site Scripting — Reflected, Stored, DOM)

## Controle Alvo
- **ID:** `AZI-02` (Controle `45/61`, Domínio 6 — Authorization & Injection)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 986–1005)
- **Ferramentas de Referência do Guia:** `ZAP, Burp Suite, DOM Invader, Schemathesis`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita — SEM Burp Suite / DOM Invader pago):** Utiliza OWASP ZAP 2.17.0 (regras ativas `40012`/`40014`) + Google Chrome Headless via CDP com listener OOB local, emitindo SARIF 2.1.0 + HAR 1.2 redigido.
2. **Lacuna 1 — Registro explícito de candidatos inconclusivos (Guia L1003):** O Guia exige que candidatos não confirmados nem refutados sejam registrados como `inconclusive`; `evaluate_azi02_xss` não expunha campo estruturado `inconclusiveCandidates` no relatório JSON nem no retorno.
3. **Lacuna 2 — Suporte a múltiplos endpoints e `application/xhtml+xml`:** A verificação de reflexão HTML inspecionava apenas `/rest/products/search?q=...` e apenas `text/html`, sem aceitar `reflected_endpoints` customizados nem `application/xhtml+xml`, e sem flag opcional `run_zap`/`run_browser` para execução modular.

## Critérios de Aceitação
- `evaluate_azi02_xss` expõe `inconclusiveCandidates` no JSON de auditoria e no retorno, aceita `reflected_endpoints`, `run_zap` e `run_browser` opcionais, e reconhece `application/xhtml+xml`.
- Respostas `application/json` nunca geram falso positivo de reflexão HTML.
- Regressão (`test_iteration115_azi02_guide_tooling`) e novo teste (`test_iteration176_azi02_neon_reeval`) passam 100%.

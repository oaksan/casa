# SDD 159 — CFG-04 Reavaliação Neon (Content-Security-Policy Enforced)

## Controle Alvo
- **ID:** `CFG-04` (Controle `28/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 615–637)
- **Ferramentas de Referência do Guia:** `csp-evaluator, OWASP ZAP`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza Google `csp-evaluator` 1.1.8 (Node.js) + OWASP ZAP 2.17.0 (`10038`/`10055`). Zero uso de Burp Suite pago.
2. **Lacuna 1 — Bypass via diretivas CSP3 (`script-src-elem` / `script-src-attr`):** `evaluate_cfg04_csp` verificava apenas `script-src` ou `default-src`. Em CSP Level 3, `script-src-elem` substitui `script-src` para elementos `<script>` e `script-src-attr` controla manipuladores inline; uma política como `default-src 'self'; script-src 'self'; script-src-elem 'unsafe-inline'` passava indevidamente.
3. **Lacuna 2 — Diretiva vazia (`script-src ;`):** Uma diretiva `script-src` sem valores (vazia) não era rejeitada como ausência de fonte efetiva.

## Critérios de Aceitação
- `script-src-elem` ou `script-src-attr` com tokens proibidos (`'unsafe-inline'`, `'unsafe-eval'`, `*`, `data:`) falha `CFG-04`.
- `script-src ;` vazio sem valores falha `CFG-04` (`no_effective_script_src`).
- Política estrita (`default-src 'self'; script-src 'self' 'nonce-abc123'; script-src-elem 'self' 'nonce-abc123'`) continua `PASS` via Google `csp-evaluator`.
- Regressão (`test_iteration98_cfg04_guide_tooling`) e novo teste (`test_iteration159_cfg04_neon_reeval`) passam 100%.

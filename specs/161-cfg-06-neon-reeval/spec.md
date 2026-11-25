# SDD 161 — CFG-06 Reavaliação Neon (X-Content-Type-Options: nosniff)

## Controle Alvo
- **ID:** `CFG-06` (Controle `30/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 660–679)
- **Ferramentas de Referência do Guia:** `OWASP ZAP (rule 10021 X-Content-Type-Options Header Missing), curl`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza OWASP ZAP 2.17.0 (Regra Passiva `10021`) + inspetor 100% de crawl de `X-Content-Type-Options: nosniff`. Zero uso de Burp Suite pago.
2. **Lacuna Identificada:** Em modo standalone (`crawled_exchanges is None`), `evaluate_cfg06_xcto` sondava apenas `["/", "/ftp/legal.md", "/metrics"]` — sem incluir uma rota de erro 404 para verificar se respostas 4xx também enviam `X-Content-Type-Options: nosniff` (requisito de 100% das respostas, incluindo 4xx/5xx, conforme Guia L679) e sem aceitar `extra_endpoints` configuráveis para aplicações arbitrárias.

## Critérios de Aceitação
- `evaluate_cfg06_xcto` aceita `extra_endpoints: list[str] | None = None` e inclui sonda de erro 404 (`/nonexistent-cfg06-probe`) no modo standalone.
- Respostas 404/500 sem `X-Content-Type-Options: nosniff` reduzem `compliancePct < 100.0` e falham `CFG-06`.
- Regressão (`test_iteration100_cfg06_guide_tooling`) e novo teste (`test_iteration161_cfg06_neon_reeval`) passam 100%.

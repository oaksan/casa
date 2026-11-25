# SDD 158 — CFG-03 Reavaliação Neon (Version Disclosure Removed)

## Controle Alvo
- **ID:** `CFG-03` (Controle `27/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 596–613)
- **Ferramentas de Referência do Guia:** `OWASP ZAP (rules 10036 Server Leaks Version, 10037 X-Powered-By), curl`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza OWASP ZAP 2.17.0 (`10036`/`10037`) + analisador de cabeçalhos e corpos HTTP. Zero uso de Burp Suite pago.
2. **Lacuna Identificada (Falso Positivo):** `evaluate_cfg03_version_disclosure` aplicava a regex `[A-Za-z-]+/[0-9]+\.[0-9]+` excluindo apenas `HTTP/`, o que gerava falsos positivos em tokens de protocolo/especificação presentes em documentação, metadados ou respostas JSON/HTML (ex.: `TLS/1.3`, `OAuth/2.0`, `OpenAPI/3.0`, `MIME/1.0`, `SPDX/2.3`, `XML/1.0`), que não revelam versão de software de servidor/framework.

## Critérios de Aceitação
- Tokens de protocolo/padrão (`TLS/1.3`, `OAuth/2.0`, `OpenAPI/3.0`, `MIME/1.0`, `SPDX/2.3`, `XML/1.0`, etc.) não disparam falso positivo em cabeçalhos ou corpos.
- Tokens reais de produto/versão (`nginx/1.24.0`, `Apache/2.4.58`, `PHP/8.2.1`, `Express/4.18.2`) continuam falhando `CFG-03`.
- Regressão (`test_iteration97_cfg03_guide_tooling`) e novo teste (`test_iteration158_cfg03_neon_reeval`) passam 100%.

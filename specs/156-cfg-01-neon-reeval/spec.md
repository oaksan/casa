# SDD 156 — CFG-01 Reavaliação Neon (Directory Browsing Disabled)

## Controle Alvo
- **ID:** `CFG-01` (Controle `25/61`, Domínio 4 — Server Configuration & Response Headers)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 556–574)
- **Ferramentas de Referência do Guia:** `OWASP ZAP (spider + directory-browsing passive rule 10033), ffuf`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza OWASP ZAP 2.17.0 (Spider + Regra Passiva `10033`) + parser de listagem de diretórios/storage. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Azure Blob Storage XML:** `parse_directory_index_body` tratava apenas AWS S3 `<ListBucketResult>` XML, omitindo listagens públicas de containers Azure Blob (`<EnumerationResults><Blobs><Blob><Name>...</Name></Blob></Blobs></EnumerationResults>`).
3. **Lacuna 2 — Padrões de autoindex IIS / Tomcat / Go `http.FileServer`:** Listagens que usam `[To Parent Directory]` (IIS) ou `Directory Listing For` sem barra inicial após `for ` (Tomcat) podiam não ser reconhecidas.

## Critérios de Aceitação
- `parse_directory_index_body` detecta e extrai itens de listagens XML Azure Blob (`<EnumerationResults>`).
- `parse_directory_index_body` detecta listagens IIS (`[To Parent Directory]`) e Tomcat (`Directory Listing For`).
- Páginas HTML normais (não-autoindex) continuam retornando `(None, [])`.
- Regressão (`test_iteration95_cfg01_guide_tooling`) e novo teste (`test_iteration156_cfg01_neon_reeval`) passam 100%.

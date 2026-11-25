# SDD 167 — AUT-01 Reavaliação Neon (No Default, Shared or Vendor-Supplied Credentials)

## Controle Alvo
- **ID:** `AUT-01` (Controle `36/61`, Domínio 5 — Authentication & Session Management)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 793–811)
- **Ferramentas de Referência do Guia:** `SecLists, scripted replay harness`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza corpus SecLists + replay harness Python com emissão de HAR 1.2 redigido e SARIF 2.1.0. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Cobertura de credenciais padrão de fornecedores via `CFG-03`:** O Passo 1 do Guia exige incluir credenciais padrão de todo produto identificado no `CFG-03`, mas apenas Tomcat e Jenkins eram mapeados dinamicamente.
3. **Lacuna 2 — Logins com redirecionamento `302`/`303` + `Set-Cookie`:** Aplicações server-side que autenticam via `POST` respondendo `302 Found` + `Set-Cookie: sid=...` (sem `2xx`) não eram contabilizadas como login bem-sucedido.
4. **Lacuna 3 — Endpoints configuráveis:** `evaluate_aut01_default_credentials` não aceitava `login_endpoints` customizados.

## Critérios de Aceitação
- Mapeamento dinâmico de `CFG-03` expandido com Grafana, Kibana/Elasticsearch, RabbitMQ, phpMyAdmin e Spring/Actuator.
- Suporte a `login_endpoints: list[str] | None = None` e detecção de login bem-sucedido em `302`/`303` com `Set-Cookie` de sessão (que não redireciona de volta para `/login` com erro).
- Regressão (`test_iteration106_aut01_guide_tooling`) e novo teste (`test_iteration167_aut01_neon_reeval`) passam 100%.

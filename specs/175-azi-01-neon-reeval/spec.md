# SDD 175 — AZI-01 Reavaliação Neon (Strong Anti-CSRF Mechanism)

## Controle Alvo
- **ID:** `AZI-01` (Controle `44/61`, Domínio 6 — Authorization & Injection)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 965–983)
- **Ferramentas de Referência do Guia:** `scripted harness, Burp Suite`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita — SEM Burp Suite pago):** Utiliza harness Python de replay anti-CSRF nos 3 modos (removido, substituído, segunda sessão) com releitura de estado, HAR 1.2 redigido e SARIF 2.1.0.
2. **Bug de Falso Positivo em `SameSite=None` (Guia L981):** `evaluate_azi01_anti_csrf` checava `"samesite=none" in sc_c.lower()` no cabeçalho `Set-Cookie` bruto, falhando indevidamente quando um cookie não-sessão (ex.: `analytics_id`, `prefs`) usava `SameSite=None`, mesmo com o cookie de sessão em `SameSite=Strict`.
3. **Lacuna 2 — Parametrização de cookie/campo:** `cookie_name` (`token`) e `state_field` (`username`) eram fixos, dificultando reuso em aplicações com nomes distintos (ex.: `sid`, `displayName`).

## Critérios de Aceitação
- `SameSite=None` só falha `AZI-01` quando aplicado a um **cookie de sessão** (`_is_session_cookie_name` ou `cookie_name`), nunca a cookies benignos de preferências/analytics.
- `evaluate_azi01_anti_csrf` aceita `cookie_name: str = "token"` e `state_field: str = "username"`.
- Regressão (`test_iteration114_azi01_guide_tooling`) e novo teste (`test_iteration175_azi01_neon_reeval`) passam 100%.

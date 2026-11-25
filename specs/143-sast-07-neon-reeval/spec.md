# SDD 143 — Reavaliação Gemini 4 Neon: Controle 12/61 (`SAST-07`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-07` — *Frameworks protect against mass assignment / unsafe auto-binding*
- **Referências**: ASVS V5.1.2 (L1); CWE-915; OWASP API6:2023; Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `semgrep`, `ZAP`, `Burp Suite` *(Burp Suite comercial substituído integralmente por OWASP ZAP gratuito + harness ativo gratuito em Python)*
- **Critério de Verificação**:
  - `PASS`: Zero achados em nível `error` de binder irrestrito **e** nenhum campo privilegiado injetado retorna alterado na leitura posterior.
  - `FAIL`: ≥ 1 achado `error` de binder irrestrito, ou ≥ 1 campo privilegiado injetado retorna alterado.

## Lacunas Identificadas na Reavaliação
1. **Cobertura de frameworks em `casa3_al1_sast.yml`**: faltavam binders irrestritos de Ruby/Rails (`params.permit!`) e PHP/Laravel (`Model::create($request->all())`, `$guarded = []`).
2. **Amplitude de campos privilegiados no probe ativo (`evaluate_sast07_mass_assignment_probe`)**: a sonda de atualização verificava apenas `role` e `isAdmin`, omitindo campos privilegiados frequentes como `is_admin`, `admin` e `permissions`.

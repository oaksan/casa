# Plano Técnico — SDD 143 (`SAST-07`)

1. Adicionar regras `CASA3-SAST-07-mass-assignment-ruby` e `CASA3-SAST-07-mass-assignment-php` em `casa3_al1_sast.yml`.
2. Expandir `evaluate_sast07_mass_assignment_probe` em `scanner.py` para injetar e verificar read-back de `role`, `isAdmin`, `is_admin`, `admin` e `permissions`, mantendo 100% de dependência apenas em ferramentas gratuitas (`semgrep` + `OWASP ZAP` + harness Python, sem Burp Suite pago).
3. Adicionar `test_iteration143_sast07_neon_reeval`, validar com `test_iteration82_sast07_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-143`.

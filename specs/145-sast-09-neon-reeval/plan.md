# Plano Técnico — SDD 145 (`SAST-09`)

1. Restringir a isenção de integridade HMAC em `CASA3-SAST-09-unsafe-deserialization-python` ao escopo da própria função (`def $FN(...): ... hmac.compare_digest(...) ...` / `if hmac.compare_digest(...): ...`).
2. Adicionar `CASA3-SAST-09-unsafe-deserialization-ruby` (`Marshal.load`, `Marshal.restore`, `YAML.load`) em `casa3_al1_sast.yml`.
3. Adicionar `test_iteration145_sast09_neon_reeval`, validar com `test_iteration84_sast09_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-145`.

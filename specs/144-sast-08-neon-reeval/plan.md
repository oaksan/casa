# Plano Técnico — SDD 144 (`SAST-08`)

1. Restringir os `pattern-not` em `CASA3-SAST-08-sql-injection` para exigir string literal estática (`"..."`) como primeiro argumento ao parametrizar via `replacements`/`bind`/array.
2. Adicionar regras `CASA3-SAST-08-sql-php` e `CASA3-SAST-08-sql-csharp` em `casa3_al1_sast.yml`.
3. Adicionar `test_iteration144_sast08_neon_reeval`, validar com `test_iteration83_sast08_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-144`.

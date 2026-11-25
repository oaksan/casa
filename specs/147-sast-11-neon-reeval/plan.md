# Plano Técnico — SDD 147 (`SAST-11`)

1. Expandir `CASA3-SAST-11-path-traversal` (JS/TS) com `fs.createReadStream`, `fs.unlink`, `fs.unlinkSync` e `fs.promises.unlink`.
2. Adicionar `CASA3-SAST-11-path-traversal-php` e `CASA3-SAST-11-path-traversal-csharp` em `casa3_al1_sast.yml`.
3. Validar com `semgrep --validate`, adicionar `test_iteration147_sast11_neon_reeval`, validar com `test_iteration86_sast11_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-147`.

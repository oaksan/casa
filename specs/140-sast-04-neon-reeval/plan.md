# Plano Técnico — SDD 140 (`SAST-04`)

1. Remover `- pattern: security.hash(...)` de `CASA3-SAST-04-weak-hash` em `casa3_al1_sast.yml` (mantendo detecção baseada exclusivamente em `crypto.createHash('md5'|'sha1')` / `createHmac`).
2. Adicionar regras `mode: taint` `CASA3-SAST-04-weak-hash-taint-php` e `CASA3-SAST-04-weak-hash-taint-csharp` em `casa3_al1_sast.yml`.
3. Atualizar `info_note` em `run_sast_checks` para usar `"note-level"` preservando a invariante do SDD 070.
4. Adicionar `test_iteration140_sast04_neon_reeval`, validar com `test_iteration79_sast04_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-140`.

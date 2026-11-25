# Plano Técnico — SDD 141 (`SAST-05`)

1. Refinar `CASA3-SAST-05-weak-password-kdf` em `casa3_al1_sast.yml` para excluir KDFs aprovados (`bcrypt.*`, `argon2.*`, `crypto.scrypt*`, `crypto.pbkdf2*`) em `this.setDataValue('password', ...)`.
2. Reforçar `evaluate_sast05_password_kdf` em `scanner.py` para exigir em `argon2.hash(...)` a declaração estaticamente verificável de `type: argon2.argon2id`, `memoryCost >= 19456` e `timeCost >= 2`, além de validar proveniência CSPRNG quando `salt:` explícito for fornecido.
3. Adicionar `test_iteration141_sast05_neon_reeval`, validar com `test_iteration80_sast05_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-141`.

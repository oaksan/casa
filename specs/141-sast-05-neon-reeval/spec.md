# SDD 141 — Reavaliação Gemini 4 Neon: Controle 10/61 (`SAST-05`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-05` — *Passwords stored using an approved memory-hard KDF with per-user salt*
- **Referências**: ASVS V2.4.1 (L2); NIST SP 800-63B §5.1.1.2 (Argon2id, scrypt, bcrypt, PBKDF2); Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `semgrep`
- **Critério de Verificação**:
  - `PASS`: Todo sink de persistência de senha usa Argon2id (`m >= 19456 KiB, t >= 2`), scrypt (`N >= 32768`), bcrypt (`cost >= 10`) ou PBKDF2-HMAC-SHA256 (`>= 600000`) com salt CSPRNG por registro.
  - `FAIL`: Qualquer sink fora desse conjunto; parâmetro de custo ou salt não determinável estaticamente; custo abaixo do piso; ou salt não-CSPRNG.

## Lacunas Identificadas na Reavaliação
1. **Falso positivo potencial em `casa3_al1_sast.yml` (`this.setDataValue('password', $HASH_FN($PWD))`)**: disparava mesmo quando `$HASH_FN` era um KDF aprovado (`bcrypt.hashSync`, `argon2.hash`, etc.).
2. **Parâmetros omitidos ou salt não-CSPRNG em `argon2.hash(...)` (`scanner.py` L3362–3373)**: `argon2.hash(pw)` sem `memoryCost`/`timeCost`/`type: argon2.argon2id` explícitos ou com `salt:` literal/estático passava sem erro, violando o critério *"any cost parameter or salt whose value or provenance is not determinable statically"* (`Test Guide` L251).

# SDD 139 — Reavaliação Gemini 4 Neon: Controle 08/61 (`SAST-03`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-03` — *No deprecated or broken cipher algorithms (DES, 3DES, RC4, Blowfish, ECB mode)*
- **Referências**: CWE-327; NIST SP 800-131A Rev.2; ASVS V6.2.5 (L2); Profile: `All`
- **Ferramentas de Referência no Test Guide**: `semgrep`, `CodeQL`
- **Critério de Verificação**:
  - `PASS`: Zero achados em nível `error` no ruleset de algoritmos banidos (DES, 3DES, RC4, Blowfish ou qualquer cifra em modo `ECB`).
  - `FAIL`: ≥ 1 achado em nível `error`.

## Lacunas Identificadas na Reavaliação
1. **Cobertura multilíngue incompleta em `casa3_al1_sast.yml`**: faltavam regras Semgrep para PHP (`openssl_encrypt`/`openssl_decrypt` com DES/3DES/RC4/BF/ECB e `mcrypt_encrypt`), Ruby (`OpenSSL::Cipher.new` com DES/RC4/BF/ECB) e imports diretos em Python (`DES.new(...)`, `DES3.new(...)`, `ARC4.new(...)`, `Blowfish.new(...)` após `from Crypto.Cipher import ...`).

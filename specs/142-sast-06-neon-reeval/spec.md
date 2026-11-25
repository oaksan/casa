# SDD 142 — Reavaliação Gemini 4 Neon: Controle 11/61 (`SAST-06`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SAST-06` — *All security-relevant randomness uses a CSPRNG*
- **Referências**: CWE-338; ASVS V6.3.1, V6.3.2 (L2); Profile: `All`
- **Ferramentas de Referência no Test Guide**: `semgrep`
- **Critério de Verificação**:
  - `PASS`: Zero caminhos de taint em nível `error` de fonte não-CSPRNG para sink relevante de segurança (token, key, nonce, salt, IV, password-reset).
  - `FAIL`: ≥ 1 caminho de taint em nível `error`.

## Lacunas Identificadas na Reavaliação
1. **Sinks genéricos com risco de falso positivo (`firstTerm`/`secondTerm`/`firstOperator`)**: variáveis aritméticas comuns disparavam `SAST-06` fora de contextos de segurança (enquanto `CaptchaModel.create(...)` já cobre CAPTCHA).
2. **Sinks de segurança ausentes e cobertura PHP/C# + seeds baseadas em tempo**: faltavam `sessionId`/`csrfToken`/`apiKey`/`authCode`, regras de `time-based seed` (`random.seed(time.time())`, `rand.Seed(time.Now()...)`) e cobertura para PHP (`rand`/`mt_rand`/`uniqid`) e C# (`System.Random`).

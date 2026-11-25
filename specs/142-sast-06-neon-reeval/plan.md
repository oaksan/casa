# Plano Técnico — SDD 142 (`SAST-06`)

1. Remover `firstTerm`/`secondTerm`/`thirdTerm`/`firstOperator`/`secondOperator` de `CASA3-SAST-06-insecure-randomness`, adicionando sinks de segurança reais (`sessionId`, `csrfToken`, `apiKey`, `authCode`, `verificationCode`).
2. Adicionar fontes/sinks adicionais em Python (`session_id`, `csrf_token`, `api_key`, `random.seed(time.time())`), Go (`rand.Seed(time.Now().UnixNano())`) e novas regras `CASA3-SAST-06-insecure-randomness-php` e `CASA3-SAST-06-insecure-randomness-csharp`.
3. Adicionar `test_iteration142_sast06_neon_reeval`, validar com `test_iteration81_sast06_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-142`.

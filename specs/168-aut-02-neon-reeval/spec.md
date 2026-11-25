# SDD 168 — AUT-02 Reavaliação Neon (Session Tokens >= 64 Bits Entropy)

## Controle Alvo
- **ID:** `AUT-02` (Controle `37/61`, Domínio 5 — Authentication & Session Management)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 814–832)
- **Ferramentas de Referência do Guia:** `Burp Sequencer, SP 800-90B entropy estimator`

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita — SEM Burp Sequencer pago):** Substitui o Burp Sequencer pago pelo estimador gratuito **NIST SP 800-90B** (expressamente previsto na L826 do Guia) + harness de coleta de 200 logins com HAR 1.2 redigido e SARIF 2.1.0.
2. **Lacuna Criptográfica Identificada em `estimate_sp800_90b_token_min_entropy`:** A soma posicional MCV assumia independência entre todas as colunas de caracteres. Um gerador fraco que repete ou espelha uma semente curta de 16 bits (ex.: `tok = secrets.token_hex(2) * 16`) obtinha > 100 bits na soma posicional e gerava **FALSO PASS**, embora sua entropia real fosse apenas 16 bits.

## Critérios de Aceitação
- `estimate_sp800_90b_token_min_entropy` deduplica colunas bijetivamente correlacionadas (via assinatura canônica de partição) e aplica limite superior de entropia por compressão (estilo SP 800-90B §6.3.4 via `zlib`).
- Tokens gerados com repetição de semente curta (`token_hex(2) * 16`) falham com `effectiveMinEntropyBits < 64.0`.
- Tokens CSPRNG legítimos de 128 bits (`secrets.token_hex(16)`) continuam passando (>= 64.0 bits).
- Regressão (`test_iteration107_aut02_guide_tooling`) e novo teste (`test_iteration168_aut02_neon_reeval`) passam 100%.

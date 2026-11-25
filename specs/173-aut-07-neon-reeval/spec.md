# SDD 173 — AUT-07 Reavaliação Neon (JWT Strong Alg, Confusion, Key Substitution & <= 24h Exp)

## Controle Alvo
- **ID:** `AUT-07` (Controle `42/61`, Domínio 5 — Authentication & Session Management)
- **Referência Normativa:** `CASA/CASA 3.0 (AL1) Test Guide.md` (linhas 919–937)
- **Ferramentas de Referência do Guia:** `jwt_tool` (referência; harness Python + PyJWT produz SARIF 2.1.0 + HAR 1.2 redigido conforme L21)

## Auditoria de Ferramentas & Lacunas Identificadas
1. **Aderência de ferramentas (100% gratuita):** Utiliza PyJWT + harness de ataque JWT forjado com SARIF 2.1.0 + HAR 1.2 redigido. Zero uso de Burp Suite pago.
2. **Lacuna 1 — Substituição de chave via header `jwk` embutido (CVE-2018-0114):** O controle exige rejeição de *key substitution*, mas `evaluate_aut07_jwt_security` testava `kid` e `jku`, sem enviar token auto-assinado com chave pública do atacante embutida no cabeçalho `jwk`.
3. **Lacuna 2 — Variante case-insensitive `alg: None`:** Alguns validadores rejeitam apenas `"none"` em minúsculas, mas aceitam `"None"`.
4. **Lacuna 3 — Extração de segredo HS256 inline:** `jwt.sign(payload, "<literal>")` sem atribuição prévia a variável `jwtSecret` não era capturado.

## Critérios de Aceitação
- `evaluate_aut07_jwt_security` envia adicionalmente `unsigned_alg_none_mixedcase` (`alg: None`) e `embedded_jwk_key_substitution` (token ES256 assinado com chave EC efêmera embutida em `header.jwk`).
- Detecção de chave HS256 fraca (< 256 bits) cobre também `jwt.sign(..., "<literal>")`.
- Regressão (`test_iteration112_aut07_guide_tooling`) e novo teste (`test_iteration173_aut07_neon_reeval`) passam 100%.

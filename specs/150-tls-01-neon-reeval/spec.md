# SDD 150 — Reavaliação Gemini 4 Neon: Controle 19/61 (`TLS-01`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `TLS-01` — *TLS enforced on all endpoints; no cleartext fallback; HTTP redirects to HTTPS*
- **Referências**: ASVS V9.1.1 (L1); Profile: `Web_Application`
- **Ferramentas de Referência no Test Guide**: `testssl.sh`, `Qualys SSL Labs`
- **Critério de Verificação**:
  - `PASS`: Todo host declarado completa handshake TLS na 443, e na porta 80 a conexão é recusada/expira ou toda requisição retorna 3xx `Location` para o mesmo host sobre `https`.
  - `FAIL`: Handshake TLS falha; ≥ 1 requisição na porta 80 respondida por algo diferente de 3xx `Location` para o mesmo host sobre `https`; ou conteúdo servido em cleartext.

## Lacunas Identificadas na Reavaliação
1. **Aceitação indevida de códigos `300`/`304`/`305` como redirect (`scanner.py` L4393)**: `300 <= c_status < 400` aceitaria `304 Not Modified` ou `300 Multiple Choices` se presentes com cabeçalho `Location`.
2. **Endpoints fixos na sonda cleartext**: `cleartext_endpoints` não permitia injetar a lista de endpoints declarados do crawl.

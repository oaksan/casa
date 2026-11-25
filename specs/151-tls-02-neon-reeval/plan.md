# Plano Técnico — SDD 151 (`TLS-02`)

1. Refinar `parse_testssl_protocols` em `scanner.py` para distinguir `"offered"`, `"not offered"` e `"unverified"` (quando `testssl.sh` reporta `"local problem"`/`"not tested"`), considerando também `severity in {"HIGH", "CRITICAL"}` em protocolos obsoletos.
2. Garantir em `evaluate_tls02_protocol_enforcement` que `tls02_pass` exige explicitamente `all(protocols_matrix.get(p) == "not offered" for p in ("SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"))` além de `bool(modern_offered)`.
3. Adicionar `test_iteration151_tls02_neon_reeval`, validar contra `test_iteration90_tls02_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-151`.

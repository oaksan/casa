# Plano — SDD 178 (AZI-04)

1. Atualizar `_parse_dns_qname` em `casa-assessment/casa_audit/scanner.py` para encerrar leitura limpa ao encontrar ponteiro de compressão DNS (`(ln & 0xC0) == 0xC0`).
2. Adicionar `oob_wait_sec: float = 0.25` e expandir `cmd_output_re` com marcadores `nt authority\\(?:system|local service|network service)` em `evaluate_azi04_cmd_injection`.
3. Adicionar `test_iteration178_azi04_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py` validando `_parse_dns_qname` com ponteiro de compressão e detecção de marcador Windows `nt authority\system`.
4. Registrar em `docs/justificativaNeon.txt`, validar regressão `test_iteration117_azi04_guide_tooling`, commitar e criar tag `sdd-178`.

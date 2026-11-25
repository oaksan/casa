# Plano — SDD 184 (OAU-04)

1. Atualizar `evaluate_oau04_state_nonce` em `casa-assessment/casa_audit/scanner.py`:
   - Calcular `varying_cols` sobre os `state` coletados para impedir que prefixos constantes inflam artificialmente a entropia >= 128 bits.
   - Reconhecer cookies de sessão (`connect.sid`, `JSESSIONID`, `session_id`, etc.) emitidos em callbacks `200`/`302` ignorando deleções (`Max-Age=0`).
   - Adicionar `run_semgrep: bool = True`.
2. Criar `test_iteration184_oau04_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar regressão `test_iteration123_oau04_guide_tooling`, commitar, criar tag `sdd-184` e fazer push.

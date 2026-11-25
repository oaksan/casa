# Plano — SDD 179 (AZI-05)

1. Atualizar `evaluate_azi05_lfi_rfi` em `casa-assessment/casa_audit/scanner.py`:
   - Expandir `lfi_marker_re` com `\[extensions\]`, `for 16-bit app support` e `127\.0\.0\.1\s+localhost`.
   - Incluir vetor Windows backslash (`win_backslash`) em `param_targets`.
   - Isolar contagem de callbacks RFI por alvo (`hits_before`) para evitar atribuição cruzada entre múltiplos `rfi_targets`.
   - Adicionar `run_rfi: bool = True`.
2. Adicionar `test_iteration179_azi05_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, rodar novo teste + regressão `test_iteration118_azi05_guide_tooling`, commitar, criar tag `sdd-179` e fazer push.

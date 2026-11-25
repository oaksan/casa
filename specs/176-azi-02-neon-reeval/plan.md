# Plano Técnico — SDD 176 (AZI-02)

1. Atualizar `evaluate_azi02_xss` em `casa-assessment/casa_audit/scanner.py`:
   - Adicionar parâmetros opcionais `reflected_endpoints: list[str] | None = None`, `run_zap: bool = True` e `run_browser: bool = True`.
   - Incluir `application/xhtml+xml` na verificação de content-type refletido e registrar `inconclusiveCandidates` estruturado no relatório JSON e retorno (conforme Guia L1003).
2. Adicionar teste unitário `test_iteration176_azi02_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Documentar em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-176` e fazer push.

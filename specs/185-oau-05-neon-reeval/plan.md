# Plano — SDD 185 (OAU-05)

1. Expandir `webview_checks` e detecção de User-Agent `Electron/` em `evaluate_oau05_system_browser_policy` (`casa-assessment/casa_audit/scanner.py`).
2. Atualizar `CASA3-OAU-05-embedded-webview-oauth` em `casa-assessment/rules/casa3_al1_oauth.yml` (incluindo `csharp` / `WebView2` / `flutter_inappwebview` / `webview_flutter`) e validar YAML com `semgrep --validate`.
3. Criar `test_iteration185_oau05_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
4. Documentar em `docs/justificativaNeon.txt`, validar regressão `test_iteration124_oau05_guide_tooling`, commitar, criar tag `sdd-185` e fazer push.

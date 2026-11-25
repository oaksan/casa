# SDD 185 — Reavaliação Neon do Controle 54/61: OAU-05

## Objetivo
Reavaliar o controle `OAU-05` (System Browser Only for Native/Mobile/Desktop OAuth — RFC 8252 §8.12) conforme `CASA/CASA 3.0 (AL1) Test Guide.md` (L1180–L1198):
1. Confirmar uso exclusivo de ferramentas gratuitas (proxy interceptador HTTP local + desempacotamento APK/IPA/ASAR + `semgrep` `CASA3-OAU-05`, sem ferramentas pagas).
2. Expandir detecção para Windows `WebView2`/`CoreWebView2`, pacotes Flutter modernos (`flutter_inappwebview`, `webview_flutter`) e User-Agent `Electron/` em capturas HAR 1.2, sincronizando `casa3_al1_oauth.yml`.

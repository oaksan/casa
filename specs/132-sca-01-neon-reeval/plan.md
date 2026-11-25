# Plano Técnico — SDD 132 (`SCA-01`)

1. **Resiliência CISA KEV (`fetch_cisa_kev_set`)**: manter fallback para `cisa_kev_cache.json` expirado caso a requisição remota falhe.
2. **Análise de Símbolos Vulneráveis & Call-Graph (`extract_osv_vuln_symbols`, `check_vulnerable_symbol_reachability`)**:
   - Extrair símbolos vulneráveis de `affected[].ecosystem_specific.imports[].symbols` e checar `experimental_analysis` do `osv-scanner`.
   - Ativar `--call-analysis=all` (ou subconjunto suportado pelo `osv-scanner` v2.7.1) quando `go.mod`/`Cargo.toml` estiver presente.
   - Para imports diretos com desestruturação nomeada (`import { a, b } from 'pkg'` / `const { a } = require('pkg')` / `from pkg import a`), confirmar se algum símbolo vulnerável consta entre os importados/chamados; caso contrário, marcar como não alcançável no nível de símbolo.
3. **Gate estrito CVSS v3.1 base ≥ 7.0**: substituir `cvss_score >= 7.0 or db_sev in {"HIGH", "CRITICAL"} or kev_matched` por `cvss_score >= 7.0 or kev_matched` (usando `db_sev` somente quando CVSS numérico não existir; default `0.0` se ausente).
4. **SARIF 2.1.0 `level: "note"`**: emitir achados abaixo de CVSS 7.0 ou inalcançáveis (e fora do KEV) no `sca-findings.sarif` com `level: "note"`, preservando a regra do SDD 070 no `log` textual.
5. **Cruzamento CISA KEV para componentes OS/Container**: após `evaluate_sca03_container_os`, inspecionar CVEs encontrados na imagem de contêiner contra `kev_set` e incluir eventuais hits KEV nos achados bloqueantes de `SCA-01` (e `level: "error"` no SARIF).
6. **Testes e Documentação**: criar `casa-assessment/tests/test_neon_reeval.py` com `test_iteration132_sca01_neon_reeval`, criar `docs/justificativaNeon.txt` com introdução metodológica e `CONTROLE 01/61: SCA-01 (Iteração SDD 132)`, executar testes, commitar, criar tag `sdd-132` e enviar ao remoto.

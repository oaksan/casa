# SDD 132 — Reavaliação Gemini 4 Neon: Controle 01/61 (`SCA-01`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SCA-01` — *No dependency contains a reachable Critical/High vulnerability, or any CISA KEV entry*
- **Referências**: ASVS 4.0.3 V14.2.1 (L1); CWE-1395; Profile: `All`
- **Ferramentas de Referência no Test Guide**: `syft`, `osv-scanner`, `NVD / OSV.dev / CISA KEV feeds`
- **Formatos de Evidência**: CycloneDX 1.5+ / SPDX 2.3+ SBOM + OASIS SARIF 2.1.0
- **Critério de Verificação**:
  - `PASS`: Zero findings com CVSS v3.1 base ≥ 7.0 **e** símbolo vulnerável alcançável por call-graph, **e** zero componentes no catálogo CISA KEV.
  - `FAIL`: ≥ 1 finding alcançável com CVSS v3.1 base ≥ 7.0, **ou** ≥ 1 componente listado no CISA KEV (alcançável ou não).

## Lacunas Identificadas na Reavaliação
1. **Alcançabilidade no nível de símbolo vulnerável (`Test Guide` L52/L57)**: `trace_package_reachability` verificava apenas import do pacote, sem consultar `affected[].ecosystem_specific.imports[].symbols` do OSV nem `experimental_analysis` / `--call-analysis` nativo do `osv-scanner`.
2. **Critério estrito CVSS v3.1 base ≥ 7.0 (`Test Guide` L57)**: a condição `cvss_score >= 7.0 or db_sev in {"HIGH", "CRITICAL"}` podia gerar falso positivo quando o vetor CVSS v3.1 computava `< 7.0` mas `db_sev` estava rotulado como `HIGH`, e o fallback OSV assumia `7.5` quando `db_sev` era vazio.
3. **Severidade SARIF 2.1.0 (`Test Guide` L23)**: achados não bloqueantes (CVSS < 7.0 ou CVSS ≥ 7.0 não alcançáveis e fora do KEV) eram descartados do `sca-findings.sarif` em vez de registrados em nível `note` sem afetar o veredito.
4. **Resiliência do feed CISA KEV**: `fetch_cisa_kev_set()` descartava o cache local (`cisa_kev_cache.json`) quando tinha >24h e a rede falhava, podendo gerar falso negativo silencioso.
5. **Cobertura CISA KEV em imagens de contêiner (`Test Guide` L52)**: CVEs de pacotes OS coletados via Trivy (`SCA-03`) não eram cruzados contra o catálogo CISA KEV em `SCA-01`.

## Requisitos da Iteração
- Manter uso exclusivo de ferramentas gratuitas do Test Guide (`syft`, `osv-scanner`, feeds NVD/OSV.dev/CISA KEV).
- Implementar as 5 melhorias acima em `casa-assessment/casa_audit/scanner.py`.
- Validar via teste unitário dedicado `test_iteration132_sca01_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py` + regressão de `test_iteration71_sca01_guide_tooling`.
- Documentar decisões e alterações em `docs/justificativaNeon.txt`.

# SDD 135 — Reavaliação Gemini 4 Neon: Controle 04/61 (`SCA-04`)

## Base Normativa (`CASA 3.0 (AL1) Test Guide.md`)
- **Controle**: `SCA-04` — *A complete, machine-readable SBOM is published for the assessed build, and it matches an SBOM the assessor generates independently*
- **Referências**: ASVS V14.2.5 (L2); NTIA Minimum Elements; CycloneDX 1.5; Profile: `All`
- **Ferramentas de Referência no Test Guide**: `syft`, `cyclonedx-cli`
- **Critério de Verificação**:
  - `PASS`: SBOM publicado é válido como CycloneDX 1.5+ ou SPDX 2.3+, todos os componentes possuem os elementos mínimos NTIA e a diferença de conjuntos `(assessor SBOM − published SBOM)` é vazia.
  - `FAIL`: SBOM ausente, não analisável ou fora de CycloneDX 1.5+/SPDX 2.3+; qualquer componente sem elemento mínimo NTIA; ou ≥ 1 componente presente no SBOM do avaliador ausente do publicado.

## Lacunas Identificadas na Reavaliação
1. **Falso `FAIL` quando o SBOM publicado reside no artefato de build/contêiner (`scanner.py` L1000–1044)**: o código registrava falha de SBOM ausente *antes* de inspecionar `/juice-shop/bom.json` / `/app/bom.json` no contêiner, tornando impossível um `PASS` mesmo se o SBOM do build fosse 100% válido.
2. **Normalização de pacotes com escopo (`group`/`name` e `purl`) na diferença de conjuntos**: `acomp.get("name")` ignorava `acomp.get("group")` (ex.: `@angular/core` emitido pelo Syft como `group="@angular", name="core"`), gerando colisões/falsos drifts.
3. **Validação NTIA aceitava placeholders SPDX (`NOASSERTION` / `NONE`)**: em SPDX 2.3+, `"supplier": "NOASSERTION"` era avaliado como verdadeiro em Python (`bool("NOASSERTION") == True`), omitindo a falta real de fornecedor.

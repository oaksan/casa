# Plano Técnico — SDD 136 (`SCA-05`)

1. Limpar entradas com espaços em `TOP_CANONICAL_NPM_PACKAGES` e adicionar `TOP_CANONICAL_PYPI_PACKAGES` + `fetch_pypi_maintainers()` (consulta à API oficial `pypi.org/pypi/<pkg>/json`) com cache em memória.
2. Expandir a verificação de typosquatting em `evaluate_sca05_malicious_and_typosquat` para cobrir pacotes npm e PyPI (diretos e transitivos de `package-lock.json` / `osv_data`) e mover o `break` para dentro do bloco de detecção confirmada (`isdisjoint`).
3. Adicionar `test_iteration136_sca05_neon_reeval` em `test_neon_reeval.py` e validar contra `test_iteration75_sca05_guide_tooling`.
4. Encerrar o Domínio 1 (`SCA-01..SCA-05`): executar toda a suíte `unittest discover`, reiniciar o daemon `casa_audit`, rodar varredura completa ao vivo contra OWASP Juice Shop, documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-136`.

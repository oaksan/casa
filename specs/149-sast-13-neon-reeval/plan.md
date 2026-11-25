# Plano Técnico — SDD 149 (`SAST-13`)

1. Expandir `CASA3-SAST-13-sensitive-logging` (JS/TS) e adicionar `CASA3-SAST-13-sensitive-logging-php` em `casa3_al1_sast.yml`.
2. Evoluir `evaluate_sast13_canary_log_replay` em `scanner.py` para suportar `extra_log_paths`, arquivos `*.log*` na raiz e canário de CVV, preservando ausência de falso positivo quando o token é gravado apenas como SHA-256 irreversível.
3. Adicionar `test_iteration149_sast13_neon_reeval`, validar contra `test_iteration88_sast13_guide_tooling`, executar fechamento do Domínio 2 (`unittest discover` integral + varredura ao vivo no OWASP Juice Shop verificando `SAST-01..SAST-13`), documentar em `docs/justificativaNeon.txt`, commitar e criar tag `sdd-149`.

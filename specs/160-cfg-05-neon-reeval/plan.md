# Plano Técnico — SDD 160 (CFG-05)

1. Endurecer `_has_valid_frame_ancestors` em `casa-assessment/casa_audit/scanner.py` com validação estrita de origens explícitas, rejeitando esquemas isolados (`https:`, `http:`, `data:`) e wildcards abertos (`*`, `https://*`, `*.*`, `*.tld`).
2. Adicionar teste unitário `test_iteration160_cfg05_neon_reeval` em `casa-assessment/tests/test_neon_reeval.py`.
3. Registrar justificativa em `docs/justificativaNeon.txt`, validar testes unitários + regressão, commitar, taggear `sdd-160` e enviar ao remoto.

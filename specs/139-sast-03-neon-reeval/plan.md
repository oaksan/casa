# Plano Técnico — SDD 139 (`SAST-03`)

1. Expandir as regras `CASA3-SAST-03-*` em `casa-assessment/rules/casa3_al1_sast.yml` para incluir PHP, Ruby e chamadas diretas Python (`DES.new`, `DES3.new`, `ARC4.new`, `Blowfish.new`) mantendo `severity: ERROR`.
2. Adicionar `test_iteration139_sast03_neon_reeval` em `test_neon_reeval.py` validando PHP, Ruby e Python (`from Crypto.Cipher import DES`) + ausência de falso positivo em AES-256-GCM.
3. Validar contra `test_iteration78_sast03_guide_tooling`, documentar em `docs/justificativaNeon.txt`, commitar, criar tag `sdd-139` e enviar ao remoto.

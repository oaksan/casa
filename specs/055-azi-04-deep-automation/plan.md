# Implementation Plan — Iteration 055 (`AZI-04`)

1. Replace the conflated static `vm.runInContext` check for `AZI-04` in `casa-assessment/casa_audit/scanner.py` with a live 20-probe OS command-injection harness backed by an ephemeral `CmdCallbackHandler` HTTP OOB listener.
2. Inspect all HTTP responses for shell output signatures (`uid=`, `root:x:0:0:`, `Windows IP Configuration`) and check OOB callback hits.
3. Emit `CASA3-AZI-04` findings into `dast_sarif_results` (`output/dast-findings.sarif`) when triggered, noting `SAST-10` CWE-94 separation cleanly.
4. Verify empirically against OWASP Juice Shop (`http://localhost:3000`), update `docs/justificativa.txt` and `tests/test_iteration1.py`, run `unittest`, commit, tag `sdd-055`, and push.

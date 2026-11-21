# SDD 077: Guide-Compliant Reference Tooling for SAST-02 (`gitleaks` Dir + Full Git History + Keystore/Cert/PEM Artifact Walker)

## Control Reference
- **Control ID**: `SAST-02`
- **Guide Requirement**: No private keys, certificates, or trust material committed to the repository (full Git history) or shipped in artifacts.
- **Reference Tooling (`CASA 3.0 (AL1) Test Guide.md`)**: `gitleaks`
- **Evidence Format**: `OASIS SARIF 2.1.0` (`ruleId`, `locations[].physicalLocation`, `level`).

## Scope & Acceptance Criteria
1. Replace the naive `git log -S "BEGIN RSA PRIVATE KEY"` heuristic (which could false-positive on commit messages) with official `gitleaks git` execution saving `output/gitleaks-sast02-git.sarif` (`SARIF 2.1.0`).
2. Integrate `gitleaks dir` private-key/trust-material detections (`private-key`, `pkcs`, `pem`, `ssh`, `pgp-private` rule IDs) directly into `evaluate_sast02_trust_material_and_keys(repo, gitleaks_dir_hits=..., gitleaks_git_hits=...)`.
3. Extend shipped-artifact walking in `evaluate_sast02_trust_material_and_keys` to cover keystore, certificate, and private-key files (`.key`, `.pem`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.kdbx`, `.pub`, `.crt`, `.cer`, `.der`, `.csr`, `encryptionkeys/`, and non-vendor archive entries `.zip/.jar/.war/.apk/.ipa/.whl`), PEM `PRIVATE KEY` blocks, and BIP-39 HDWallet private-key seeds.
4. Expose `Gitleaks v8.30.1` clearly in `SAST-02`'s tool metadata and reference `gitleaks-sast01.sarif` / `gitleaks-sast02-git.sarif` in `SAST-02` logs, passing live against OWASP Juice Shop (`FAIL` with deterministic trust-material + Gitleaks private-key findings).

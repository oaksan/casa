import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR / "casa-assessment"))

import casa_audit.scanner as sc


class TestNeonReeval(unittest.TestCase):
    """SDD 132–192: Gemini 4 Neon re-evaluation of all 61 CASA 3.0 AL1 controls against Test Guide."""

    def test_iteration132_sca01_neon_reeval(self) -> None:
        # 1. Verify vulnerable symbol extraction from OSV schema
        sample_vuln = {
            "id": "GHSA-test-1234",
            "affected": [
                {
                    "ecosystem_specific": {
                        "imports": [{"path": "demo-lib", "symbols": ["dangerParse", "evilExec"]}]
                    }
                }
            ],
        }
        syms = sc.extract_osv_vuln_symbols(sample_vuln)
        self.assertEqual(syms, ["dangerParse", "evilExec"])

        # 2. Verify symbol-level reachability distinguishes named safe import vs vulnerable import
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "lib").mkdir()
            (repo / "lib" / "safe.ts").write_text(
                "import { safeHelper } from 'demo-lib';\nexport const x = safeHelper();\n",
                encoding="utf-8",
            )
            is_dir, traces = sc.analyze_package_reachability(repo, "demo-lib")
            self.assertTrue(is_dir)
            sym_reach, _ = sc.check_vulnerable_symbol_reachability(
                repo, "demo-lib", ["dangerParse"], True, traces, True
            )
            self.assertFalse(sym_reach, "Named import of only safeHelper must not mark dangerParse reachable")

            # Native osv-scanner called=False overrides reachability
            sym_reach_called_false, _ = sc.check_vulnerable_symbol_reachability(
                repo, "demo-lib", [], True, traces, True, osv_called_flag=False
            )
            self.assertFalse(sym_reach_called_false)

            # Now import the vulnerable symbol explicitly
            (repo / "lib" / "vuln.ts").write_text(
                "import { dangerParse } from 'demo-lib';\nexport const y = dangerParse('a');\n",
                encoding="utf-8",
            )
            _, traces2 = sc.analyze_package_reachability(repo, "demo-lib")
            sym_reach2, sym_traces2 = sc.check_vulnerable_symbol_reachability(
                repo, "demo-lib", ["dangerParse"], True, traces2, True
            )
            self.assertTrue(sym_reach2)
            self.assertTrue(any("dangerParse" in t for t in sym_traces2))

        # 3. Verify CISA KEV stale-cache fallback when network is unavailable
        with tempfile.TemporaryDirectory() as td_out:
            out_dir = Path(td_out)
            cache = out_dir / "cisa_kev_cache.json"
            cache.write_text(json.dumps(["CVE-2024-99999"]), encoding="utf-8")
            # Force mtime older than 24h
            import os

            old_ts = 1000000000
            os.utime(cache, (old_ts, old_ts))
            with mock.patch.object(sc, "OUTPUT_DIR", out_dir), mock.patch(
                "urllib.request.urlopen", side_effect=OSError("offline")
            ):
                kevs = sc.fetch_cisa_kev_set()
                self.assertIn("CVE-2024-99999", kevs)

        # 4. Verify strict CVSS >= 7.0 gate + SARIF note emission + container KEV cross-check
        with tempfile.TemporaryDirectory() as td_repo, tempfile.TemporaryDirectory() as td_out2:
            repo = Path(td_repo)
            out_dir = Path(td_out2)
            (repo / "lib").mkdir()
            (repo / "lib" / "app.ts").write_text(
                "import { safeFn } from 'pkg-a';\nimport pkgB from 'pkg-b';\nexport const r = [safeFn(), pkgB()];\n",
                encoding="utf-8",
            )
            (repo / "package.json").write_text(
                json.dumps({"name": "demo", "dependencies": {"pkg-a": "1.0.0", "pkg-b": "1.0.0"}}),
                encoding="utf-8",
            )
            fake_osv = {
                "results": [
                    {
                        "source": {"path": str(repo / "package-lock.json")},
                        "packages": [
                            {
                                "package": {"name": "pkg-a", "version": "1.0.0"},
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-low-cvss",
                                        "aliases": ["CVE-2025-0001"],
                                        # CVSS 3.1 vector with base score 5.3 even though db_sev says HIGH
                                        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
                                        "database_specific": {"severity": "HIGH"},
                                    }
                                ],
                            },
                            {
                                "package": {"name": "pkg-b", "version": "1.0.0"},
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-kev-hit",
                                        "aliases": ["CVE-2024-99999"],
                                        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
                                    }
                                ],
                            },
                        ],
                    }
                ]
            }
            with mock.patch.object(sc, "OUTPUT_DIR", out_dir), mock.patch.object(
                sc, "generate_sbom_with_syft", return_value=({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}, [{"name": "pkg-a", "version": "1.0.0"}], True)
            ), mock.patch.object(
                sc, "fetch_cisa_kev_set", return_value={"CVE-2024-99999", "CVE-2024-88888"}
            ), mock.patch.object(
                sc, "run_osv_scanner_for_sca01", return_value=(fake_osv, 2, True)
            ), mock.patch.object(
                sc, "evaluate_sca02_dependencies", return_value=([], [], {"eol_or_deprecated": 0, "low_scorecard": 0, "untrusted_registry": 0})
            ), mock.patch.object(
                sc, "evaluate_sca03_container_os", return_value=("PASS", [], ["openssl@1.1 (CVE-2024-88888 will_not_fix)"], [], [], "mock-img")
            ), mock.patch.object(
                sc, "evaluate_sca04_sbom_completeness", return_value=("PASS", [], [], "mock")
            ), mock.patch.object(
                sc, "evaluate_sca05_malicious_and_typosquat", return_value=("PASS", [], [], "mock")
            ):
                res = sc.run_sca_checks(repo)
                self.assertEqual(res["SCA-01"]["verdict"], "FAIL")
                # pkg-a has CVSS 5.3 -> must NOT block even with db_sev=HIGH; recorded as SARIF note
                self.assertNotIn("pkg-a@1.0.0", res["SCA-01"]["log"])
                # pkg-b KEV and container OS KEV must both block
                self.assertIn("pkg-b@1.0.0", res["SCA-01"]["log"])
                self.assertIn("CVE-2024-88888", res["SCA-01"]["log"])
                # SDD 070 invariant: no "non-blocking" or "informational" in log
                self.assertNotIn("non-blocking", res["SCA-01"]["log"].lower())
                self.assertNotIn("informational", res["SCA-01"]["log"].lower())
                sarif = json.loads((out_dir / "sca-findings.sarif").read_text(encoding="utf-8"))
                sca01_sarif = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CASA3-SCA-01"]
                self.assertTrue(any(r["level"] == "note" and "pkg-a@1.0.0" in r["message"]["text"] for r in sca01_sarif))
                self.assertTrue(any(r["level"] == "error" and "pkg-b@1.0.0" in r["message"]["text"] for r in sca01_sarif))
                self.assertTrue(any(r["level"] == "error" and "CVE-2024-88888" in r["message"]["text"] for r in sca01_sarif))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 01/61: SCA-01 (Iteração SDD 132)", just_neon)

    def test_iteration133_sca02_neon_reeval(self) -> None:
        # 1. Verify developer-controlled HTTPS mirror pinned by digest passes (yarn.lock + PyPI --hash)
        #    while unpinned mirror fails, and no fabricated "Legacy 0.x" EOL error is raised
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as td_out:
            repo = Path(td)
            out_dir = Path(td_out)
            (repo / "yarn.lock").write_text(
                '"pinned-lib@^0.4.0":\n'
                '  version "0.4.2"\n'
                '  resolved "https://mirror.corp.example/npm/pinned-lib-0.4.2.tgz"\n'
                '  integrity sha512-abcdef123456\n\n'
                '"unpinned-lib@^1.0.0":\n'
                '  version "1.0.0"\n'
                '  resolved "https://mirror.corp.example/npm/unpinned-lib-1.0.0.tgz"\n',
                encoding="utf-8",
            )
            (repo / "requirements.txt").write_text(
                "--index-url https://mirror.corp.example/simple/\n"
                "safe-py==1.2.3 --hash=sha256:" + ("a" * 64) + "\n"
                "unpinned-py==1.0.0\n",
                encoding="utf-8",
            )

            class _FakeResp:
                def __init__(self, payload: dict):
                    self._b = json.dumps(payload).encode("utf-8")

                def read(self) -> bytes:
                    return self._b

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

            def _fake_urlopen(url, timeout=5):
                u = str(url)
                if "registry.npmjs.org/pinned-lib" in u:
                    return _FakeResp(
                        {
                            "dist-tags": {"latest": "9.0.0"},
                            "versions": {"0.4.2": {}, "9.0.0": {}},
                            "repository": {"url": "https://github.com/org/pinned-lib"},
                        }
                    )
                if "registry.npmjs.org/unpinned-lib" in u:
                    return _FakeResp({"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}})
                if "api.securityscorecards.dev" in u:
                    return _FakeResp({"score": 7.0, "checks": [{"name": "Maintained", "score": 8}]})
                if "pypi.org/pypi" in u:
                    return _FakeResp({"info": {"classifiers": []}, "releases": {"1.2.3": [], "1.0.0": []}})
                raise OSError("network disabled")

            with mock.patch.object(sc, "OUTPUT_DIR", out_dir), mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen):
                fails, sarifs, stats = sc.evaluate_sca02_dependencies(
                    repo,
                    [
                        ("npm", "pinned-lib", "0.4.0"),
                        ("npm", "unpinned-lib", "1.0.0"),
                        ("PyPI", "safe-py", "1.2.3"),
                        ("PyPI", "unpinned-py", "1.0.0"),
                    ],
                )
            joined = "\n".join(fails)
            # pinned-lib@0.4.2 has latest=9.0.0, HTTPS mirror with sha512 integrity, Maintained=8 -> MUST PASS (no artificial Legacy 0.x)
            self.assertNotIn("pinned-lib@0.4.2", joined)
            # safe-py has HTTPS mirror + sha256 --hash -> MUST PASS
            self.assertNotIn("safe-py@1.2.3", joined)
            # unpinned-lib and unpinned-py MUST FAIL on untrusted/unpinned registry
            self.assertIn("unpinned-lib", joined)
            self.assertIn("unpinned-py", joined)
            self.assertEqual(stats["untrusted_registry"], 2)
            # SARIF note emitted when Scorecard result is absent (safe-py)
            self.assertTrue(any(r["level"] == "note" and "safe-py" in r["message"]["text"] for r in sarifs))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 02/61: SCA-02 (Iteração SDD 133)", just_neon)

    def test_iteration134_sca03_neon_reeval(self) -> None:
        # 1. Verify will_not_fix without documented mitigation blocks; with lab-verified mitigation is excluded;
        #    end_of_life always blocks; not_affected is excluded.
        trivy_sample = {
            "Metadata": {"OS": {"Family": "debian", "Name": "13.7"}},
            "Results": [
                {
                    "Class": "os-pkgs",
                    "Packages": [
                        {"Name": "tar", "Version": "1.35", "Identifier": {"PURL": "pkg:deb/debian/tar@1.35"}},
                        {"Name": "gzip", "Version": "1.12", "Identifier": {"PURL": "pkg:deb/debian/gzip@1.12"}},
                        {"Name": "zlib1g", "Version": "1.3", "Identifier": {"PURL": "pkg:deb/debian/zlib1g@1.3"}},
                        {"Name": "curl", "Version": "8.0", "Identifier": {"PURL": "pkg:deb/debian/curl@8.0"}},
                    ],
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2025-1001", "PkgName": "tar", "InstalledVersion": "1.35", "Severity": "HIGH", "Status": "will_not_fix"},
                        {"VulnerabilityID": "CVE-2025-1002", "PkgName": "gzip", "InstalledVersion": "1.12", "Severity": "HIGH", "Status": "will_not_fix"},
                        {"VulnerabilityID": "CVE-2025-1003", "PkgName": "zlib1g", "InstalledVersion": "1.3", "Severity": "CRITICAL", "Status": "end_of_life"},
                        {"VulnerabilityID": "CVE-2025-1004", "PkgName": "curl", "InstalledVersion": "8.0", "Severity": "HIGH", "Status": "not_affected"},
                    ],
                }
            ],
        }
        _, blocking, excluded, sarifs, _ = sc.parse_trivy_os_report(
            trivy_sample, documented_mitigations={"CVE-2025-1002"}
        )
        joined_blk = "\n".join(blocking)
        joined_exc = "\n".join(excluded)
        self.assertIn("CVE-2025-1001", joined_blk)
        self.assertIn("no documented mitigation", joined_blk)
        self.assertIn("CVE-2025-1003", joined_blk)
        self.assertNotIn("CVE-2025-1002", joined_blk)
        self.assertNotIn("CVE-2025-1004", joined_blk)
        self.assertIn("CVE-2025-1002", joined_exc)
        self.assertIn("CVE-2025-1004", joined_exc)
        self.assertEqual(len(sarifs), 2)

        # 2. Verify no fabricated Debian 13 package list when Trivy/Docker cannot inspect a digest-pinned Dockerfile
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "Dockerfile").write_text(
                "FROM gcr.io/distroless/nodejs22-debian13@sha256:" + ("a" * 64) + "\n",
                encoding="utf-8",
            )
            fake_fail = mock.Mock(returncode=1, stdout="", stderr="no daemon")
            with mock.patch("subprocess.run", return_value=fake_fail):
                verdict, blk, _, _, comps, _ = sc.evaluate_sca03_container_os(repo)
            self.assertEqual(verdict, "Not_Covered")
            self.assertEqual(blk, [])
            self.assertEqual(comps, [])

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 03/61: SCA-03 (Iteração SDD 134)", just_neon)

    def test_iteration135_sca04_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            assessor_comps = [
                {
                    "type": "library",
                    "bom-ref": "pkg:npm/%40angular/core@18.0.0",
                    "group": "@angular",
                    "name": "core",
                    "version": "18.0.0",
                    "supplier": {"name": "Google"},
                    "purl": "pkg:npm/%40angular/core@18.0.0",
                }
            ]
            # 1. SPDX 2.3 SBOM with NOASSERTION supplier MUST FAIL NTIA validation
            spdx_bad = {
                "spdxVersion": "SPDX-2.3",
                "creationInfo": {"created": "2026-11-25T00:00:00Z", "creators": ["Tool: syft"]},
                "packages": [
                    {
                        "SPDXID": "SPDXRef-pkg-1",
                        "name": "@angular/core",
                        "versionInfo": "18.0.0",
                        "supplier": "NOASSERTION",
                        "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/%40angular/core@18.0.0"}],
                    }
                ],
                "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-pkg-1"}],
            }
            (repo / "sbom.spdx.json").write_text(json.dumps(spdx_bad), encoding="utf-8")
            a_path = repo / "assessor.cdx.json"
            a_path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": assessor_comps}), encoding="utf-8")
            v_bad, f_bad, _, _ = sc.evaluate_sca04_sbom_completeness(repo, assessor_comps, a_path)
            self.assertEqual(v_bad, "FAIL")
            self.assertTrue(any("NTIA" in f for f in f_bad))

            # 2. Valid SPDX 2.3 SBOM with real supplier + matching scoped group/name passes
            spdx_good = json.loads(json.dumps(spdx_bad))
            spdx_good["packages"][0]["supplier"] = "Organization: Google"
            (repo / "sbom.spdx.json").write_text(json.dumps(spdx_good), encoding="utf-8")
            v_good, f_good, _, _ = sc.evaluate_sca04_sbom_completeness(repo, assessor_comps, a_path)
            self.assertEqual(v_good, "PASS", f"Expected PASS, got {f_good}")

            # 3. Container-only valid SBOM must NOT carry stale repo-missing failure
            (repo / "sbom.spdx.json").unlink()
            (repo / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            fake_proc = mock.Mock(returncode=0, stdout=json.dumps(spdx_good), stderr="")
            with mock.patch("subprocess.run", return_value=fake_proc):
                v_ctr, f_ctr, _, _ = sc.evaluate_sca04_sbom_completeness(repo, assessor_comps, a_path)
            self.assertEqual(v_ctr, "PASS", f"Container SBOM should PASS without stale repo-missing error, got {f_ctr}")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 04/61: SCA-04 (Iteração SDD 135)", just_neon)

    def test_iteration136_sca05_neon_reeval(self) -> None:
        # 1. Verify TOP_CANONICAL_NPM_PACKAGES has no stray leading whitespace
        self.assertTrue(all(p == p.strip() for p in sc.TOP_CANONICAL_NPM_PACKAGES))

        # 2. Verify PyPI Levenshtein=1 typosquat AND transitive npm lockfile typosquat are detected
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "requirements.txt").write_text("requestss==2.31.0\n", encoding="utf-8")
            (repo / "package.json").write_text(
                json.dumps({"name": "demo", "dependencies": {"express": "4.22.1"}}),
                encoding="utf-8",
            )
            (repo / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/lodasg": {"version": "1.0.0"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            def _fake_npm(pkg: str):
                if pkg == "lodasg":
                    return (["attacker"], "clone")
                if pkg == "lodash":
                    return (["jdalton"], "lodash")
                return ([], "")

            def _fake_pypi(pkg: str):
                if pkg == "requestss":
                    return (["evil@example.com"], "http")
                if pkg == "requests":
                    return (["kennethreitz@example.com"], "http")
                return ([], "")

            with mock.patch.object(sc, "fetch_npm_maintainers", side_effect=_fake_npm), mock.patch.object(
                sc, "fetch_pypi_maintainers", side_effect=_fake_pypi
            ), mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout='{"results":[]}', stderr="")):
                verdict, fails, sarifs, _ = sc.evaluate_sca05_malicious_and_typosquat(repo)

            joined = "\n".join(fails)
            self.assertEqual(verdict, "FAIL")
            self.assertIn("requestss@2.31.0", joined)
            self.assertIn("lodasg@1.0.0", joined)
            self.assertTrue(any("requirements.txt" in str(s) for s in sarifs))
            self.assertTrue(any("package-lock.json" in str(s) for s in sarifs))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 05/61: SCA-05 (Iteração SDD 136)", just_neon)

    def test_iteration137_sast01_neon_reeval(self) -> None:
        import zipfile

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            # 1. Shipped archive (.zip) with hardcoded API key must be caught
            (repo / "releases").mkdir()
            with zipfile.ZipFile(repo / "releases" / "bundle.zip", "w") as zf:
                zf.writestr("config/app.yml", "api_key: 'demo_secret_99887766554433221100AABBCC'\n")
            # 2. Unverified Gitleaks hit must NOT claim verified=true; verified hit MUST claim verified=true
            gl_hits = [
                {"File": str(repo / "app.ts"), "StartLine": 5, "RuleID": "generic-api-key", "Description": "Generic Key", "Entropy": 4.2, "Verified": False},
                {"File": str(repo / "live.ts"), "StartLine": 9, "RuleID": "aws-access-token", "Description": "Live AWS Key", "Entropy": 4.5, "Verified": True},
            ]
            findings, sarifs = sc.evaluate_sast01_secrets_and_entropy(repo, gitleaks_hits=gl_hits)
            joined = "\n".join(findings)
            self.assertIn("releases/bundle.zip!config/app.yml", joined)
            self.assertTrue(any("app.ts:5" in f and "verified=false; triaged=error" in f for f in findings))
            self.assertTrue(any("live.ts:9" in f and "verified=true" in f for f in findings))
            self.assertTrue(all(s["level"] == "error" for s in sarifs))

        # 3. Verify Juice Shop hardcoded literal removed from Semgrep SAST-01 rule
        rules_txt = (ROOT_DIR / "casa-assessment" / "rules" / "casa3_al1_sast.yml").read_text(encoding="utf-8")
        self.assertNotIn("6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie", rules_txt)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 06/61: SAST-01 (Iteração SDD 137)", just_neon)

    def test_iteration138_sast02_neon_reeval(self) -> None:
        import io
        import tarfile

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            # 1. Shipped tarball (.tar.gz) containing keystore & PEM block
            (repo / "releases").mkdir()
            tb_path = repo / "releases" / "dist.tar.gz"
            with tarfile.open(tb_path, "w:gz") as tf:
                cert_bytes = b"MIIB-dummy-cert"
                ti1 = tarfile.TarInfo("tls/prod.p12")
                ti1.size = len(cert_bytes)
                tf.addfile(ti1, io.BytesIO(cert_bytes))

                pem_bytes = b"-----BEGIN " + b"EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
                ti2 = tarfile.TarInfo("cfg/inline.txt")
                ti2.size = len(pem_bytes)
                tf.addfile(ti2, io.BytesIO(pem_bytes))

            # 2. Root-level Go file with embedded PEM private key block
            (repo / "main.go").write_text(
                'package main\nconst k = "-----BEGIN ' + 'RSA PRIVATE KEY-----\\nXYZ"\n',
                encoding="utf-8",
            )
            findings, sarifs = sc.evaluate_sast02_trust_material_and_keys(
                repo, gitleaks_dir_hits=[], gitleaks_git_hits=[]
            )
            joined = "\n".join(findings)
            self.assertIn("releases/dist.tar.gz!tls/prod.p12", joined)
            self.assertIn("releases/dist.tar.gz!cfg/inline.txt", joined)
            self.assertIn("main.go:2", joined)
            self.assertGreaterEqual(len(sarifs), 3)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 07/61: SAST-02 (Iteração SDD 138)", just_neon)

    def test_iteration139_sast03_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            (src / "bad.php").write_text(
                "<?php $ct = openssl_encrypt($msg, 'aes-128-ecb', $key);\n",
                encoding="utf-8",
            )
            (src / "bad.rb").write_text(
                "require 'openssl'\nc = OpenSSL::Cipher.new('des-ede3-cbc')\n",
                encoding="utf-8",
            )
            (src / "bad_imp.py").write_text(
                "from Crypto.Cipher import DES\nc = DES.new(b'12345678', DES.MODE_CBC)\n",
                encoding="utf-8",
            )
            verdict, findings, sarifs, _ = sc.evaluate_sast03_banned_ciphers(repo)
            self.assertEqual(verdict, "FAIL")
            joined = "\n".join(findings)
            for fn in ("bad.php", "bad.rb", "bad_imp.py"):
                self.assertIn(fn, joined, f"Missing SAST-03 hit for {fn} in:\n{joined}")
            self.assertGreaterEqual(len(sarifs), 3)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 08/61: SAST-03 (Iteração SDD 139)", just_neon)

    def test_iteration140_sast04_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            # 1. Generic security.hash() using SHA-256 must NOT false-positive
            (src / "safe_wrapper.ts").write_text(
                "import crypto from 'crypto';\nexport const security = { hash: (x: string) => crypto.createHash('sha256').update(x).digest('hex') };\nexport const h = security.hash('abc');\n",
                encoding="utf-8",
            )
            v_ok, f_ok, _, _, _ = sc.evaluate_sast04_weak_hashes(repo)
            self.assertEqual(v_ok, "PASS", f"Safe security.hash() must PASS, got {f_ok}")

            # 2. PHP and C# weak-hash taint into security sinks MUST FAIL
            (src / "bad.php").write_text(
                "<?php $h = sha1($pwd); $token = $h;\n",
                encoding="utf-8",
            )
            (src / "Bad.cs").write_text(
                "using System.Security.Cryptography;\nclass C { void F(byte[] b) { var d = SHA1.HashData(b); var token = d; } }\n",
                encoding="utf-8",
            )
            v_fail, f_fail, err_s, _, _ = sc.evaluate_sast04_weak_hashes(repo)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            self.assertIn("bad.php", joined)
            self.assertIn("Bad.cs", joined)
            self.assertGreaterEqual(len(err_s), 2)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 09/61: SAST-04 (Iteração SDD 140)", just_neon)

    def test_iteration141_sast05_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            # 1. Sequelize setDataValue using bcrypt.hashSync(pw, 12) must NOT false-positive
            (src / "model_ok.ts").write_text(
                "import bcrypt from 'bcrypt';\nclass U { setPassword(pw: string) { this.setDataValue('password', bcrypt.hashSync(pw, 12)); } }\n",
                encoding="utf-8",
            )
            f_ok, _ = sc.evaluate_sast05_password_kdf(repo)
            self.assertEqual(f_ok, [], f"Approved bcrypt in setDataValue must PASS, got {f_ok}")

            # 2. argon2.hash() omitting memoryCost/timeCost/type or passing static salt must FAIL
            (src / "argon_bad.ts").write_text(
                "import argon2 from 'argon2';\n"
                "export const h1 = (pw: string) => argon2.hash(pw);\n"
                "export const h2 = (pw: string) => argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, salt: 'fixed-salt' });\n",
                encoding="utf-8",
            )
            f_bad, s_bad = sc.evaluate_sast05_password_kdf(repo)
            joined = "\n".join(f_bad)
            self.assertIn("UNPROVABLE ARGON2 VARIANT", joined)
            self.assertIn("NON-CSPRNG ARGON2 SALT", joined)
            self.assertGreaterEqual(len(s_bad), 2)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 10/61: SAST-05 (Iteração SDD 141)", just_neon)

    def test_iteration142_sast06_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            # 1. Non-security arithmetic variable firstTerm using Math.random() must NOT false-positive
            (src / "quiz.ts").write_text(
                "export const mk = () => { const firstTerm = Math.floor(Math.random() * 10); return firstTerm; };\n",
                encoding="utf-8",
            )
            v_ok, f_ok, _, _ = sc.evaluate_sast06_csprng_randomness(repo)
            self.assertEqual(v_ok, "PASS", f"Non-security firstTerm must PASS, got {f_ok}")

            # 2. PHP mt_rand -> csrfToken, C# Random -> token, TS Math.random -> sessionId MUST FAIL
            (src / "bad.php").write_text("<?php $r = mt_rand(); $csrfToken = $r;\n", encoding="utf-8")
            (src / "Bad.cs").write_text("using System;\nclass C { void F() { var r = new Random(); var token = r.Next(); } }\n", encoding="utf-8")
            (src / "bad.ts").write_text("export const s = () => { const sessionId = Math.random().toString(36); return sessionId; };\n", encoding="utf-8")
            v_fail, f_fail, sarifs, _ = sc.evaluate_sast06_csprng_randomness(repo)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fn in ("bad.php", "Bad.cs", "bad.ts"):
                self.assertIn(fn, joined, f"Missing SAST-06 hit for {fn} in:\n{joined}")
            self.assertGreaterEqual(len(sarifs), 3)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 11/61: SAST-06 (Iteração SDD 142)", just_neon)

    def test_iteration143_sast07_neon_reeval(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            (src / "user.rb").write_text("def up\n  User.update(params.permit!)\nend\n", encoding="utf-8")
            (src / "User.php").write_text("<?php class User { protected $guarded = []; }\n", encoding="utf-8")
            v_fail, f_fail, sarifs, _ = sc.evaluate_sast07_framework_binding(repo)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            self.assertIn("user.rb", joined)
            self.assertIn("User.php", joined)
            self.assertGreaterEqual(len(sarifs), 2)

            # Verify active probe detects snake_case is_admin read-back without Burp Suite
            class _H(BaseHTTPRequestHandler):
                is_admin = False

                def log_message(self, *a):
                    pass

                def do_POST(self):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    if self.path.endswith("/login"):
                        self.wfile.write(json.dumps({"token": "t1"}).encode())
                    else:
                        self.wfile.write(json.dumps({"data": {"id": 1, "role": "user"}}).encode())

                def do_PUT(self):
                    ln = int(self.headers.get("Content-Length", "0"))
                    body = json.loads(self.rfile.read(ln).decode() or "{}")
                    if body.get("is_admin") is True:
                        type(self).is_admin = True
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"data": {"id": 1, "is_admin": type(self).is_admin}}).encode())

                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"data": {"id": 1, "is_admin": type(self).is_admin}}).encode())

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                hit = sc.evaluate_sast07_mass_assignment_probe(
                    f"http://127.0.0.1:{port}",
                    dast_sarif_path=repo / "none.sarif",
                    sarif_out=repo / "none2.sarif",
                )
                self.assertIsNotNone(hit)
                self.assertIn("is_admin=True", hit)
            finally:
                srv.shutdown()
                srv.server_close()

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 12/61: SAST-07 (Iteração SDD 143)", just_neon)

    def test_iteration144_sast08_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            # Concatenated SQL with dummy bind array must STILL fail; PHP and C# SQLi taint must FAIL
            (src / "bad_concat.ts").write_text(
                "export const q = (req: any, db: any) => db.query('SELECT * FROM u WHERE name=' + req.query.n, [1]);\n",
                encoding="utf-8",
            )
            (src / "bad.php").write_text(
                "<?php $id = $_GET['id']; mysqli_query($conn, 'SELECT * FROM u WHERE id=' . $id);\n",
                encoding="utf-8",
            )
            (src / "Bad.cs").write_text(
                "class C { void F() { var q = Request.Query[\"u\"]; new SqlCommand(\"SELECT * FROM u WHERE n=\" + q, conn); } }\n",
                encoding="utf-8",
            )
            v_fail, f_fail, sarifs, _ = sc.evaluate_sast08_sql_injection(repo)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fn in ("bad_concat.ts", "bad.php", "Bad.cs"):
                self.assertIn(fn, joined, f"Missing SAST-08 hit for {fn} in:\n{joined}")
            self.assertGreaterEqual(len(sarifs), 3)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 13/61: SAST-08 (Iteração SDD 144)", just_neon)

    def test_iteration145_sast09_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            # 1. Unrelated hmac.compare_digest in helper_fn must NOT suppress unguarded pickle.loads in bad_fn
            (src / "mixed.py").write_text(
                "import hmac, pickle\n"
                "def helper_fn(a, b): return hmac.compare_digest(a, b)\n"
                "def bad_fn(blob): return pickle.loads(blob)\n",
                encoding="utf-8",
            )
            # 2. Ruby Marshal.load & YAML.load must FAIL
            (src / "bad.rb").write_text(
                "def load_obj(raw)\n  Marshal.load(raw)\nend\n",
                encoding="utf-8",
            )
            v_fail, f_fail, sarifs, _ = sc.evaluate_sast09_deserialization(repo)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            self.assertIn("mixed.py", joined)
            self.assertIn("bad.rb", joined)
            self.assertGreaterEqual(len(sarifs), 2)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 14/61: SAST-09 (Iteração SDD 145)", just_neon)

    def test_iteration146_sast10_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            (src / "dyn.ts").write_text(
                "import { spawn } from 'child_process';\nexport const run = (req: any) => spawn(req.query.cmd, [], { shell: true });\n",
                encoding="utf-8",
            )
            (src / "dyn.php").write_text("<?php shell_exec($_GET['cmd']);\n", encoding="utf-8")
            (src / "Dyn.cs").write_text("class C { void F() { var m = Request.Query[\"asm\"]; Assembly.Load(m); } }\n", encoding="utf-8")
            v_fail, f_fail, sarifs, _ = sc.evaluate_sast10_dynamic_execution(repo)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fn in ("dyn.ts", "dyn.php", "Dyn.cs"):
                self.assertIn(fn, joined, f"Missing SAST-10 hit for {fn} in:\n{joined}")
            self.assertGreaterEqual(len(sarifs), 3)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 15/61: SAST-10 (Iteração SDD 146)", just_neon)

    def test_iteration147_sast11_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            (src / "bad_stream.ts").write_text(
                "import fs from 'fs';\nexport const rd = (req: any) => fs.createReadStream('/var/data/' + req.query.f);\n",
                encoding="utf-8",
            )
            (src / "bad.php").write_text("<?php echo file_get_contents('/srv/' . $_GET['f']);\n", encoding="utf-8")
            (src / "Bad.cs").write_text("class C { void F() { var p = Request.Query[\"f\"]; File.ReadAllText(\"/srv/\" + p); } }\n", encoding="utf-8")
            v_fail, f_fail, sarifs, _ = sc.evaluate_sast11_path_traversal(repo)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fn in ("bad_stream.ts", "bad.php", "Bad.cs"):
                self.assertIn(fn, joined, f"Missing SAST-11 hit for {fn} in:\n{joined}")
            self.assertGreaterEqual(len(sarifs), 3)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 16/61: SAST-11 (Iteração SDD 147)", just_neon)

    def test_iteration148_sast12_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            # 1. Parameterized ${JWT_SECRET} in docker-compose + /run/secrets/ mount must NOT false-positive
            (repo / "docker-compose.yml").write_text(
                "services:\n  app:\n    image: myapp:1.0\n    environment:\n      - JWT_SECRET=${JWT_SECRET}\n    volumes:\n      - /run/secrets/db_pass:/run/secrets/db_pass:ro\n",
                encoding="utf-8",
            )
            f_ok, _, sdk_txt = sc.evaluate_sast12_secrets_management_and_iac(repo, run_trivy=False, run_docker=False)
            self.assertEqual(f_ok, [], f"Parameterized compose with /run/secrets mount must PASS, got {f_ok}")
            self.assertIn("/run/secrets/", sdk_txt)

            # 2. Generic `trivy image --scanners secret` catches baked secrets on ANY image (no juice-shop hardcoding)
            def _fake_sub(cmd, **kw):
                if cmd[0] == "docker":
                    return mock.Mock(returncode=0, stdout='["PATH=/usr/bin"]', stderr="")
                if "image" in cmd and "--scanners" in cmd:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps(
                            {
                                "Results": [
                                    {
                                        "Target": "app/config.yml",
                                        "Secrets": [{"RuleID": "private-key", "Title": "Asymmetric Private Key", "StartLine": 4}],
                                    }
                                ]
                            }
                        ),
                        stderr="",
                    )
                return mock.Mock(returncode=1, stdout="", stderr="")

            with mock.patch("subprocess.run", side_effect=_fake_sub):
                f_img, s_img, _ = sc.evaluate_sast12_secrets_management_and_iac(repo, run_trivy=False, run_docker=True)
            self.assertTrue(any("[TRIVY IMAGE LAYER SECRET private-key]" in f for f in f_img))
            self.assertTrue(any(s["ruleId"] == "CASA3-SAST-12-trivy-image-private-key" for s in s_img))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 17/61: SAST-12 (Iteração SDD 148)", just_neon)

    def test_iteration149_sast13_neon_reeval(self) -> None:
        import hashlib
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            src = repo / "src"
            src.mkdir()
            (src / "bad_cvv.ts").write_text("export const f = (req: any, logger: any) => logger.info(req.body.cvv);\n", encoding="utf-8")
            (src / "bad.php").write_text("<?php error_log($_POST['password']);\n", encoding="utf-8")
            v_fail, f_fail, sarifs, _ = sc.evaluate_sast13_sensitive_logging(repo)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            self.assertIn("bad_cvv.ts", joined)
            self.assertIn("bad.php", joined)
            self.assertGreaterEqual(len(sarifs), 2)

            # Canary replay: logging ONLY irreversible SHA-256 hash of token must PASS (0 hits)
            ext_log = repo / "runtime_sink.log"

            class _HashedHandler(BaseHTTPRequestHandler):
                def log_message(self, *a):
                    pass

                def _h(self):
                    auth = self.headers.get("Authorization", "")
                    h_tok = hashlib.sha256(auth.encode()).hexdigest()
                    with ext_log.open("a", encoding="utf-8") as fh:
                        fh.write(f"auth_sha256={h_tok}\n")
                    self.send_response(200)
                    self.end_headers()

                def do_GET(self):
                    self._h()

                def do_POST(self):
                    ln = int(self.headers.get("Content-Length", "0"))
                    _ = self.rfile.read(ln)
                    self._h()

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _HashedHandler)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                hits_hashed = sc.evaluate_sast13_canary_log_replay(
                    f"http://127.0.0.1:{port}", repo, sarif_out=repo / "no.sarif", extra_log_paths=[ext_log]
                )
                self.assertEqual(hits_hashed, [], f"Hashed token log must NOT trigger canary leak: {hits_hashed}")
            finally:
                srv.shutdown()
                srv.server_close()

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 18/61: SAST-13 (Iteração SDD 149)", just_neon)

    def test_iteration150_tls01_neon_reeval(self) -> None:
        fake_ok_tls = {"executed": True, "handshakeOk": True, "protocolsOffered": ["TLS 1.3"], "scanProblem": None, "scanResult": []}
        with mock.patch.object(sc, "run_testssl_scan", return_value=fake_ok_tls):
            # 1. HTTP 304 with Location is NOT a valid redirect -> FAIL
            res_304 = sc.evaluate_tls01_transport_enforcement(
                "https://app.example.com",
                http_probe_fn=lambda u: (304, {"location": "https://app.example.com/"}, ""),
                endpoints=["/"],
            )
            self.assertEqual(res_304["verdict"], "FAIL")

            # 2. HTTP 301 redirecting to a DIFFERENT host -> FAIL
            res_cross = sc.evaluate_tls01_transport_enforcement(
                "https://app.example.com",
                http_probe_fn=lambda u: (301, {"location": "https://evil.example.com/"}, ""),
                endpoints=["/"],
            )
            self.assertEqual(res_cross["verdict"], "FAIL")

            # 3. Port 80 connection refused (status=0) + valid TLS 443 -> PASS (Test Guide L444)
            res_refused = sc.evaluate_tls01_transport_enforcement(
                "https://app.example.com",
                http_probe_fn=lambda u: (0, {}, "Connection refused"),
                endpoints=["/", "/api/status"],
            )
            self.assertEqual(res_refused["verdict"], "PASS")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 19/61: TLS-01 (Iteração SDD 150)", just_neon)

    def test_iteration151_tls02_neon_reeval(self) -> None:
        # 1. Local problem on SSLv3 must mark SSLv3 unverified and FAIL (not silently assume not offered)
        fake_unverified = {
            "executed": True,
            "scanResult": [
                {
                    "protocols": [
                        {"id": "SSLv2", "finding": "not offered", "severity": "OK"},
                        {"id": "SSLv3", "finding": "Local problem: openssl lacks SSLv3", "severity": "WARN"},
                        {"id": "TLS1", "finding": "not offered", "severity": "OK"},
                        {"id": "TLS1_1", "finding": "not offered", "severity": "OK"},
                        {"id": "TLS1_2", "finding": "offered", "severity": "OK"},
                        {"id": "TLS1_3", "finding": "offered", "severity": "OK"},
                    ]
                }
            ],
        }
        res_unv = sc.evaluate_tls02_protocol_enforcement("https://app.example.com", testssl_info=fake_unverified)
        self.assertEqual(res_unv["verdict"], "FAIL")
        self.assertEqual(res_unv["protocols"]["SSLv3"], "unverified")
        self.assertIn("SSLv3", res_unv["deprecatedUnverified"])

        # 2. All 4 legacy protocols explicitly not offered + TLS 1.3 offered -> PASS
        fake_clean = {
            "executed": True,
            "scanResult": [
                {
                    "protocols": [
                        {"id": "SSLv2", "finding": "not offered", "severity": "OK"},
                        {"id": "SSLv3", "finding": "not offered", "severity": "OK"},
                        {"id": "TLS1", "finding": "not offered", "severity": "OK"},
                        {"id": "TLS1_1", "finding": "not offered", "severity": "OK"},
                        {"id": "TLS1_2", "finding": "not offered", "severity": "INFO"},
                        {"id": "TLS1_3", "finding": "offered with final", "severity": "OK"},
                    ]
                }
            ],
        }
        res_ok = sc.evaluate_tls02_protocol_enforcement("https://app.example.com", testssl_info=fake_clean)
        self.assertEqual(res_ok["verdict"], "PASS")
        self.assertEqual(res_ok["modernOffered"], ["TLS 1.3"])

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 20/61: TLS-02 (Iteração SDD 151)", just_neon)

    def test_iteration152_tls03_neon_reeval(self) -> None:
        # 1. ECDHE CBC-SHA1 inside FS_ciphers + cipherlist_AVERAGE must FAIL TLS-03
        fake_cbc_fs = {
            "executed": True,
            "scanResult": [
                {
                    "ciphers": [
                        {"id": "cipherlist_STRONG_FS", "finding": "offered"},
                        {"id": "cipherlist_AVERAGE", "finding": "offered"},
                    ],
                    "fs": [
                        {"id": "FS", "finding": "offered"},
                        {"id": "FS_ciphers", "finding": "ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA"},
                    ],
                }
            ],
        }
        res_fail = sc.evaluate_tls03_cipher_enforcement("https://app.example.com", testssl_info=fake_cbc_fs)
        self.assertEqual(res_fail["verdict"], "FAIL")
        self.assertTrue(any("CBC-SHA1:ECDHE-RSA-AES128-SHA" in b for b in res_fail["cipherAudit"]["bannedSuitesOffered"]))
        self.assertTrue(any("AVERAGE/LEGACY-CBC" in b for b in res_fail["cipherAudit"]["bannedSuitesOffered"]))

        # 2. Pure AEAD ECDHE + TLS 1.3 suites -> PASS
        fake_clean = {
            "executed": True,
            "scanResult": [
                {
                    "ciphers": [
                        {"id": "cipherlist_STRONG_FS", "finding": "offered"},
                        {"id": "cipherlist_AVERAGE", "finding": "not offered"},
                    ],
                    "fs": [
                        {"id": "FS", "finding": "offered"},
                        {"id": "FS_ciphers", "finding": "TLS_AES_256_GCM_SHA384 ECDHE-RSA-AES256-GCM-SHA384"},
                    ],
                }
            ],
        }
        res_ok = sc.evaluate_tls03_cipher_enforcement("https://app.example.com", testssl_info=fake_clean)
        self.assertEqual(res_ok["verdict"], "PASS")
        self.assertEqual(res_ok["cipherAudit"]["bannedSuitesOffered"], [])

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 21/61: TLS-03 (Iteração SDD 152)", just_neon)

    def test_iteration153_tls04_neon_reeval(self) -> None:
        # 1. Certificate with future notBefore must FAIL
        future_cert = {
            "executed": True,
            "scanResult": [
                {
                    "serverDefaults": [
                        {"id": "cert_commonName", "finding": "app.example.com"},
                        {"id": "cert_chain_of_trust", "severity": "OK", "finding": "passed"},
                        {"id": "cert_trust", "severity": "OK", "finding": "Ok via SAN and CN"},
                        {"id": "cert_notBefore", "finding": "2099-01-01 00:00"},
                        {"id": "cert_notAfter", "finding": "2099-12-31 00:00"},
                        {"id": "cert_expirationStatus", "severity": "OK", "finding": "365 days"},
                    ]
                }
            ],
        }
        r_fut = sc.evaluate_tls04_certificate_validation("https://app.example.com", testssl_info=future_cert)
        self.assertEqual(r_fut["verdict"], "FAIL")
        self.assertFalse(r_fut["certAudit"]["notExpired"])

        # 2. Short-lived cert (< 30d) emits clean advisory warning without 'informational'
        short_cert = {
            "executed": True,
            "scanResult": [
                {
                    "serverDefaults": [
                        {"id": "cert_commonName", "finding": "app.example.com"},
                        {"id": "cert_chain_of_trust", "severity": "OK", "finding": "passed"},
                        {"id": "cert_trust", "severity": "OK", "finding": "Ok via SAN and CN"},
                        {"id": "cert_notBefore", "finding": "2020-01-01 00:00"},
                        {"id": "cert_expirationStatus", "severity": "WARN", "finding": "10 days"},
                    ]
                }
            ],
        }
        r_sh = sc.evaluate_tls04_certificate_validation("https://app.example.com", testssl_info=short_cert)
        self.assertEqual(r_sh["verdict"], "PASS")
        self.assertTrue(any("< 30 days" in w for w in r_sh["certAudit"]["warnings"]))
        self.assertFalse(any("informational" in w.lower() for w in r_sh["certAudit"]["warnings"]))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 22/61: TLS-04 (Iteração SDD 153)", just_neon)

    def test_iteration154_tls05_neon_reeval(self) -> None:
        # 1. RFC 6797 quoted max-age="31536000" + parenthesized testssl HSTS_time -> PASS
        fake_hsts = {
            "executed": True,
            "scanResult": [
                {
                    "headerResponse": [
                        {"id": "HSTS_time", "finding": ">= 365 days (31536000 seconds)"},
                        {"id": "HSTS_subdomains", "finding": "includes subdomains"},
                    ]
                }
            ],
        }
        r_ok = sc.evaluate_tls05_hsts_enforcement(
            "https://app.example.com",
            testssl_info=fake_hsts,
            endpoints=["/"],
            http_probe_fn=lambda ep: (200, {"strict-transport-security": 'max-age="31536000"; includeSubDomains'}, ""),
        )
        self.assertEqual(r_ok["verdict"], "PASS", f"Quoted max-age must PASS, got {r_ok}")
        self.assertEqual(r_ok["HSTS_time"], 31536000)

        # 2. Unreachable endpoint reports connection error explicitly
        r_err = sc.evaluate_tls05_hsts_enforcement(
            "https://app.example.com",
            testssl_info=fake_hsts,
            endpoints=["/"],
            http_probe_fn=lambda ep: (0, {}, "timeout"),
        )
        self.assertEqual(r_err["verdict"], "FAIL")
        self.assertTrue(any("unreachable" in v for v in r_err["violations"]))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 23/61: TLS-05 (Iteração SDD 154)", just_neon)

    def test_iteration155_tls06_neon_reeval(self) -> None:
        # 1. LOW/MEDIUM vulnerability entries are informational only -> PASS (Test Guide L549)
        fake_med = {
            "executed": True,
            "scanResult": [
                {
                    "vulnerabilities": [
                        {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"},
                        {"id": "ROBOT", "severity": "OK", "finding": "not vulnerable"},
                        {"id": "secure_renego", "severity": "OK", "finding": "supported"},
                        {"id": "secure_client_renego", "severity": "MEDIUM", "finding": "client renego advisory"},
                        {"id": "CRIME_TLS", "severity": "OK", "finding": "not vulnerable"},
                        {"id": "ticketbleed", "severity": "OK", "finding": "not vulnerable"},
                    ]
                }
            ],
        }
        r_pass = sc.evaluate_tls06_vulnerabilities("https://app.example.com", testssl_info=fake_med)
        self.assertEqual(r_pass["verdict"], "PASS")
        self.assertEqual(len(r_pass["vulnAudit"]["informationalFindings"]), 1)

        # 2. HIGH entry on secure_client_renego -> FAIL
        fake_high = json.loads(json.dumps(fake_med))
        fake_high["scanResult"][0]["vulnerabilities"][3]["severity"] = "HIGH"
        r_fail = sc.evaluate_tls06_vulnerabilities("https://app.example.com", testssl_info=fake_high)
        self.assertEqual(r_fail["verdict"], "FAIL")
        self.assertTrue(any("secure_client_renego" in h for h in r_fail["vulnAudit"]["highOrCriticalFindings"]))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 24/61: TLS-06 (Iteração SDD 155)", just_neon)

    def test_iteration156_cfg01_neon_reeval(self) -> None:
        # 1. Azure Blob EnumerationResults XML detected
        azure_xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<EnumerationResults ContainerName="https://acct.blob.core.windows.net/backups">'
            "<Blobs><Blob><Name>db-dump.sql</Name></Blob><Blob><Name>keys.json</Name></Blob></Blobs>"
            "</EnumerationResults>"
        )
        fmt_az, items_az = sc.parse_directory_index_body(
            "/backups", 200, {"content-type": "application/xml"}, azure_xml
        )
        self.assertEqual(fmt_az, "Azure Blob EnumerationResults XML")
        self.assertEqual(items_az, ["db-dump.sql", "keys.json"])

        # 2. IIS [To Parent Directory] listing detected
        iis_html = (
            '<html><head><title>srv - /uploads/</title></head><body><pre>'
            '<a href="/">[To Parent Directory]</a><br>'
            '<a href="/uploads/report.pdf">report.pdf</a>'
            "</pre></body></html>"
        )
        fmt_iis, items_iis = sc.parse_directory_index_body(
            "/uploads", 200, {"content-type": "text/html"}, iis_html
        )
        self.assertEqual(fmt_iis, "Web Server Autoindex HTML")
        self.assertIn("report.pdf", items_iis)

        # 3. Normal HTML page does not false-positive
        normal_html = "<html><body><h1>Welcome</h1><p>No directory listing here.</p></body></html>"
        fmt_ok, items_ok = sc.parse_directory_index_body(
            "/", 200, {"content-type": "text/html"}, normal_html
        )
        self.assertIsNone(fmt_ok)
        self.assertEqual(items_ok, [])

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 25/61: CFG-01 (Iteração SDD 156)", just_neon)

    def test_iteration157_cfg02_neon_reeval(self) -> None:
        empty_nuc = {"executed": True, "matches": [], "version": "3.11.1"}

        # 1. Clean crawled responses -> PASS
        r_clean = sc.evaluate_cfg02_debug_modes(
            "https://app.example.com",
            crawled_exchanges=[
                {"url": "https://app.example.com/", "status": 200, "body": "<html><body>Production Home</body></html>"},
                {"url": "https://app.example.com/missing", "status": 404, "body": '{"error":"Not found"}'},
            ],
            nuclei_result=empty_nuc,
        )
        self.assertEqual(r_clean["verdict"], "PASS")

        # 2. Django DEBUG=True & Werkzeug interactive debugger in crawled responses -> FAIL
        r_dbg = sc.evaluate_cfg02_debug_modes(
            "https://app.example.com",
            crawled_exchanges=[
                {
                    "url": "https://app.example.com/nonexistent",
                    "status": 404,
                    "body": "<html><body>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</body></html>",
                },
                {
                    "url": "https://app.example.com/crash",
                    "status": 500,
                    "body": "<html><title>Werkzeug Debugger</title><script>var EVALEX = true;</script></html>",
                },
            ],
            nuclei_result=empty_nuc,
        )
        self.assertEqual(r_dbg["verdict"], "FAIL")
        tids = {f["templateId"] for f in r_dbg["findings"]}
        self.assertIn("django-debug-true", tids)
        self.assertIn("werkzeug-debugger", tids)
        self.assertTrue(all(f["kind"] == "debug_marker" for f in r_dbg["findings"]))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 26/61: CFG-02 (Iteração SDD 157)", just_neon)

    def test_iteration158_cfg03_neon_reeval(self) -> None:
        empty_zap = {"executed": True, "alerts": []}

        # 1. Protocol/standard tokens (TLS/1.3, OAuth/2.0, OpenAPI/3.0, SPDX/2.3) must NOT false-positive
        r_clean = sc.evaluate_cfg03_version_disclosure(
            "https://app.example.com",
            crawled_exchanges=[
                {
                    "method": "GET",
                    "url": "https://app.example.com/",
                    "status": 200,
                    "headers": {"content-type": "text/html", "x-spec": "OpenAPI/3.0"},
                    "body": "<html><body>Supports TLS/1.3, OAuth/2.0, MIME/1.0 and SPDX/2.3 formats.</body></html>",
                }
            ],
            zap_report=empty_zap,
        )
        self.assertEqual(r_clean["verdict"], "PASS", f"Expected PASS, got {r_clean}")

        # 2. Real product/version token in body or header still fails
        r_leak = sc.evaluate_cfg03_version_disclosure(
            "https://app.example.com",
            crawled_exchanges=[
                {
                    "method": "GET",
                    "url": "https://app.example.com/error",
                    "status": 502,
                    "headers": {"content-type": "text/html"},
                    "body": "<html><body><hr><center>nginx/1.24.0</center></body></html>",
                }
            ],
            zap_report=empty_zap,
        )
        self.assertEqual(r_leak["verdict"], "FAIL")
        self.assertTrue(any(f["token"] == "nginx/1.24.0" for f in r_leak["findings"]))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 27/61: CFG-03 (Iteração SDD 158)", just_neon)

    def test_iteration159_cfg04_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            csp_json = Path(td) / "csp.json"
            # 1. CSP3 bypass via script-src-elem 'unsafe-inline' -> FAIL
            r_elem = sc.evaluate_cfg04_csp(
                "https://app.example.com",
                crawled_exchanges=[
                    {
                        "method": "GET",
                        "url": "https://app.example.com/",
                        "status": 200,
                        "headers": {
                            "content-type": "text/html",
                            "content-security-policy": "default-src 'self'; script-src 'self'; script-src-elem 'unsafe-inline'",
                        },
                        "body": "<html><body>App</body></html>",
                    }
                ],
                csp_out_path=csp_json,
            )
            self.assertEqual(r_elem["verdict"], "FAIL")
            self.assertTrue(any("script-src-elem" in t for f in r_elem["findings"] for t in f.get("tokens", [])))

            # 2. Empty script-src directive -> FAIL
            r_empty = sc.evaluate_cfg04_csp(
                "https://app.example.com",
                crawled_exchanges=[
                    {
                        "method": "GET",
                        "url": "https://app.example.com/",
                        "status": 200,
                        "headers": {
                            "content-type": "text/html",
                            "content-security-policy": "default-src 'self'; script-src ;",
                        },
                        "body": "<html><body>App</body></html>",
                    }
                ],
                csp_out_path=csp_json,
            )
            self.assertEqual(r_empty["verdict"], "FAIL")
            self.assertEqual(r_empty["findings"][0]["issue"], "no_effective_script_src")

            # 3. Strict CSP3 with safe script-src-elem -> PASS
            r_ok = sc.evaluate_cfg04_csp(
                "https://app.example.com",
                crawled_exchanges=[
                    {
                        "method": "GET",
                        "url": "https://app.example.com/",
                        "status": 200,
                        "headers": {
                            "content-type": "text/html",
                            "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-rAnd0m123'; script-src-elem 'self' 'nonce-rAnd0m123'",
                        },
                        "body": "<html><body>App</body></html>",
                    }
                ],
                csp_out_path=csp_json,
            )
            self.assertEqual(r_ok["verdict"], "PASS", f"Expected PASS, got {r_ok}")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 28/61: CFG-04 (Iteração SDD 159)", just_neon)

    def test_iteration160_cfg05_neon_reeval(self) -> None:
        # 1. Scheme-only wildcards and bare host wildcards must be rejected
        for bad_csp in [
            "frame-ancestors https:",
            "frame-ancestors http:",
            "frame-ancestors data:",
            "frame-ancestors https://*",
            "frame-ancestors *.*",
            "frame-ancestors *.com",
            "frame-ancestors 'self' https:",
        ]:
            ok, _ = sc._has_valid_frame_ancestors(bad_csp)
            self.assertFalse(ok, f"Expected '{bad_csp}' to be rejected")

        # 2. Explicit allowlisted origins and 'none'/'self' must be accepted
        for good_csp in [
            "frame-ancestors 'none'",
            "frame-ancestors 'self'",
            "frame-ancestors 'self' https://partner.example.com",
            "frame-ancestors https://*.trusted.example.com:8443",
        ]:
            ok, _ = sc._has_valid_frame_ancestors(good_csp)
            self.assertTrue(ok, f"Expected '{good_csp}' to be accepted")

        # 3. End-to-end evaluate_cfg05_clickjacking fails on frame-ancestors https:
        r_bad = sc.evaluate_cfg05_clickjacking(
            "https://app.example.com",
            crawled_exchanges=[
                {
                    "method": "GET",
                    "url": "https://app.example.com/",
                    "status": 200,
                    "headers": {
                        "content-type": "text/html",
                        "content-security-policy": "frame-ancestors https:",
                    },
                    "body": "<html><body>App</body></html>",
                }
            ],
            zap_report={"executed": True, "alerts": []},
        )
        self.assertEqual(r_bad["verdict"], "FAIL")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 29/61: CFG-05 (Iteração SDD 160)", just_neon)

    def test_iteration161_cfg06_neon_reeval(self) -> None:
        empty_zap = {"executed": True, "alerts": []}

        # 1. 404 error response missing X-Content-Type-Options: nosniff -> FAIL (< 100%)
        def _probe_404_missing(ep: str):
            if "nonexistent" in ep:
                return 404, {"content-type": "text/html"}, "Not Found"
            return 200, {"content-type": "application/json", "x-content-type-options": "nosniff"}, "{}"

        r_fail = sc.evaluate_cfg06_xcto(
            "https://app.example.com",
            http_probe_fn=_probe_404_missing,
            zap_report=empty_zap,
        )
        self.assertEqual(r_fail["verdict"], "FAIL")
        self.assertLess(r_fail["compliancePct"], 100.0)
        self.assertTrue(any(v["status"] == 404 for v in r_fail["violations"]))

        # 2. Custom extra_endpoints all sending nosniff (including 404) -> PASS (100%)
        def _probe_all_ok(ep: str):
            st = 404 if "missing" in ep else 200
            return st, {"content-type": "application/json", "x-content-type-options": "nosniff"}, "{}"

        r_ok = sc.evaluate_cfg06_xcto(
            "https://app.example.com",
            extra_endpoints=["/", "/api/items", "/static/app.js", "/missing"],
            http_probe_fn=_probe_all_ok,
            zap_report=empty_zap,
        )
        self.assertEqual(r_ok["verdict"], "PASS")
        self.assertEqual(r_ok["compliancePct"], 100.0)
        self.assertEqual(r_ok["totalResponses"], 4)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 30/61: CFG-06 (Iteração SDD 161)", just_neon)

    def test_iteration162_cfg07_neon_reeval(self) -> None:
        empty_zap = {"executed": True, "alerts": []}

        # 1. Custom auth_headers & endpoints with Cache-Control: no-store, private -> PASS
        def _probe_ok(ep: str, method: str = "GET", headers=None, body=None):
            if (headers or {}).get("Authorization") == "Bearer custom-tok":
                return 200, {"cache-control": "no-store, private"}, '{"balance":100}'
            return 401, {}, ""

        r_ok = sc.evaluate_cfg07_anti_caching(
            "https://app.example.com",
            auth_headers={"Authorization": "Bearer custom-tok"},
            endpoints=["/api/v1/profile", "/api/v1/billing"],
            http_probe_fn=_probe_ok,
            zap_report=empty_zap,
        )
        self.assertEqual(r_ok["verdict"], "PASS")
        self.assertTrue(r_ok["authenticated"])
        self.assertEqual(r_ok["checkedCount"], 2)

        # 2. Contradictory Cache-Control: public, no-store -> FAIL
        def _probe_pub(ep: str, method: str = "GET", headers=None, body=None):
            return 200, {"cache-control": "public, no-store"}, '{"balance":100}'

        r_pub = sc.evaluate_cfg07_anti_caching(
            "https://app.example.com",
            auth_headers={"Authorization": "Bearer custom-tok"},
            endpoints=["/api/v1/profile"],
            http_probe_fn=_probe_pub,
            zap_report=empty_zap,
        )
        self.assertEqual(r_pub["verdict"], "FAIL")
        self.assertTrue(any("public" in f["detail"] for f in r_pub["findings"]))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 31/61: CFG-07 (Iteração SDD 162)", just_neon)

    def test_iteration163_cfg08_neon_reeval(self) -> None:
        empty_zap = {"executed": True, "alerts": []}

        # 1. Server with buggy startsWith("https://app.example.com") reflects prefix-matching origin -> FAIL
        def _probe_prefix_bug(ep: str, method: str = "GET", headers=None, body=None):
            orig = (headers or {}).get("Origin", "")
            if orig.startswith("https://app.example.com"):
                return 200, {"access-control-allow-origin": orig, "access-control-allow-credentials": "true"}, "{}"
            return 200, {}, "{}"

        r_pref = sc.evaluate_cfg08_cors(
            "https://app.example.com",
            endpoints=[("GET", "/api/v1/me", {}, True)],
            http_probe_fn=_probe_prefix_bug,
            zap_report=empty_zap,
        )
        self.assertEqual(r_pref["verdict"], "FAIL")
        self.assertEqual(r_pref["prefixOrigin"], "https://app.example.com.evil.example.com")
        self.assertTrue(any(f["violationType"] == "reflected_prefix_matching_origin" for f in r_pref["findings"]))

        # 2. Exact-match allowlist rejecting all untrusted origins -> PASS
        def _probe_exact(ep: str, method: str = "GET", headers=None, body=None):
            orig = (headers or {}).get("Origin", "")
            if orig == "https://app.example.com":
                return 200, {"access-control-allow-origin": orig}, "{}"
            return 200, {}, "{}"

        r_ok = sc.evaluate_cfg08_cors(
            "https://app.example.com",
            endpoints=[("GET", "/api/v1/me", {}, True)],
            http_probe_fn=_probe_exact,
            zap_report=empty_zap,
        )
        self.assertEqual(r_ok["verdict"], "PASS")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 32/61: CFG-08 (Iteração SDD 163)", just_neon)

    def test_iteration164_cfg09_neon_reeval(self) -> None:
        empty_zap = {"executed": True, "alerts": []}

        # 1. Multi-language leaks (PHP fatal + SQLSTATE, Go panic, Ruby backtrace, Python frame) -> FAIL
        leaks = [
            {"method": "GET", "url": "https://app.example.com/php", "status": 500, "headers": {}, "body": "Fatal error: Uncaught PDOException: SQLSTATE[42S02]: Table not found on line 42"},
            {"method": "GET", "url": "https://app.example.com/go", "status": 500, "headers": {}, "body": "panic: runtime error\ngoroutine 19 [running]:\nmain.handler() server.go:88 +0x1a"},
            {"method": "GET", "url": "https://app.example.com/rb", "status": 500, "headers": {}, "body": "app/controllers/orders.rb:17:in `create'"},
            {"method": "GET", "url": "https://app.example.com/py", "status": 500, "headers": {}, "body": '  File "views.py", line 91, in get_profile'},
        ]
        r_leak = sc.evaluate_cfg09_error_disclosure(
            "https://app.example.com",
            crawled_exchanges=leaks,
            http_probe_fn=lambda ep, method="GET", headers=None, body=None: (400, {}, '{"error":"Bad request"}'),
            zap_report=empty_zap,
        )
        self.assertEqual(r_leak["verdict"], "FAIL")
        self.assertEqual(len(r_leak["findings"]), 4)
        all_cls = {c for f in r_leak["findings"] for c in f["classes"]}
        self.assertTrue({"stack_frame", "sql_fragment"}.issubset(all_cls))

        # 2. Malformed JSON probe is sent and generic 400 passes cleanly
        seen_bodies: list[bytes | None] = []

        def _capture_probe(ep, method="GET", headers=None, body=None):
            seen_bodies.append(body)
            return 400, {"content-type": "application/json"}, '{"error":"Invalid request"}'

        r_ok = sc.evaluate_cfg09_error_disclosure(
            "https://app.example.com",
            crawled_exchanges=[],
            http_probe_fn=_capture_probe,
            zap_report=empty_zap,
        )
        self.assertEqual(r_ok["verdict"], "PASS")
        self.assertIn(b"{invalid-json", seen_bodies)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 33/61: CFG-09 (Iteração SDD 164)", just_neon)

    def test_iteration165_cfg10_neon_reeval(self) -> None:
        empty_zap = {"executed": True, "alerts": [], "urls": []}

        # 1. Volatile timestamp/UUID in auth vs unauth response still detected via normalized LCS >= 0.90 -> FAIL
        call_n = {"i": 0}

        def _probe_volatile(ep: str, method: str = "GET", headers=None, body=None):
            call_n["i"] += 1
            if ep == "/":
                return 200, {}, "<html><body>Home</body></html>"
            if ep == "/api/v1/account":
                ts = "2026-11-25T10:00:01Z" if call_n["i"] % 2 else "2026-11-25T10:00:09Z"
                uid = "11111111-1111-1111-1111-111111111111" if call_n["i"] % 2 else "22222222-2222-2222-2222-222222222222"
                return 200, {"content-type": "application/json"}, f'{{"account":"vip","reqId":"{uid}","ts":"{ts}"}}'
            return 404, {}, ""

        r_vol = sc.evaluate_cfg10_admin_reachability(
            "https://app.example.com",
            auth_headers={"Authorization": "Bearer tok"},
            auth_routes=["/api/v1/account"],
            admin_wordlist=["/admin"],
            http_probe_fn=_probe_volatile,
            zap_report=empty_zap,
        )
        self.assertEqual(r_vol["verdict"], "FAIL")
        self.assertTrue(any(f["kind"] == "authenticated_route_bypass" for f in r_vol["findings"]))

        # 2. Admin login gate (password input) with no auth_headers -> PASS; exposed admin panel -> FAIL
        def _probe_login_gate(ep: str, method: str = "GET", headers=None, body=None):
            if ep == "/admin":
                return 200, {"content-type": "text/html"}, '<html><body><form><input type="password" name="pw"></form></body></html>'
            return 401, {}, ""

        r_gate = sc.evaluate_cfg10_admin_reachability(
            "https://app.example.com",
            auth_headers={},
            auth_routes=[],
            admin_wordlist=["/admin"],
            http_probe_fn=_probe_login_gate,
            zap_report=empty_zap,
        )
        self.assertEqual(r_gate["verdict"], "PASS")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 34/61: CFG-10 (Iteração SDD 165)", just_neon)

    def test_iteration166_cfg11_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            # 1. Expanded can-i-take-over-xyz provider (.zendesk.com) on extra_hosts subdomain -> FAIL
            def _lookup(h: str):
                if h == "support.app.example.com":
                    return [h, "unclaimed-corp.zendesk.com"], "NXDOMAIN", []
                return [h], "NOERROR", ["93.184.216.34"]

            r_sub = sc.evaluate_cfg11_dns_takeover(
                "http://127.0.0.1:9",
                root_body="<html><body>Healthy primary</body></html>",
                extra_hosts=["support.app.example.com", "docs.app.example.com"],
                cname_lookup_fn=_lookup,
                dnsx_out_path=tdp / "dnsx.json",
                nuclei_jsonl_path=tdp / "nuc.jsonl",
                nuclei_sarif_path=tdp / "nuc.sarif",
            )
            self.assertEqual(r_sub["verdict"], "FAIL")
            self.assertGreaterEqual(r_sub["providersCount"], 24)
            self.assertIn("support.app.example.com", r_sub["auditedHosts"])
            self.assertTrue(any("zendesk.com" in f["detail"] for f in r_sub["findings"]))

            # 2. Clean primary + clean extra_hosts -> PASS
            r_ok = sc.evaluate_cfg11_dns_takeover(
                "http://127.0.0.1:9",
                root_body="<html><body>Healthy primary</body></html>",
                extra_hosts=["docs.app.example.com"],
                cname_lookup_fn=lambda h: ([h], "NOERROR", ["93.184.216.34"]),
                dnsx_out_path=tdp / "dnsx_ok.json",
                nuclei_jsonl_path=tdp / "nuc_ok.jsonl",
                nuclei_sarif_path=tdp / "nuc_ok.sarif",
            )
            self.assertEqual(r_ok["verdict"], "PASS", f"Expected PASS, got {r_ok}")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 35/61: CFG-11 (Iteração SDD 166)", just_neon)

    def test_iteration167_aut01_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            har_p = Path(td) / "aut01.har"

            # 1. Dynamic vendor default from CFG-03 (RabbitMQ guest:guest) accepted via 302 + Set-Cookie -> FAIL
            def _probe_302(ep: str, method: str = "GET", headers=None, body=None):
                if ep == "/custom/signin" and method == "POST":
                    d = json.loads((body or b"{}").decode("utf-8"))
                    u = d.get("username") or d.get("email") or ""
                    p = d.get("password") or ""
                    if u == "guest" and p == "guest":
                        return 302, {"location": "/dashboard", "set-cookie": "sid=rabbit_sess_123; Path=/; HttpOnly"}, ""
                    return 302, {"location": "/login?error=1"}, ""
                return 200, {}, "<html><body>Portal</body></html>"

            r_fail = sc.evaluate_aut01_default_credentials(
                "https://app.example.com",
                cfg03_findings=[{"token": "RabbitMQ/3.12", "detail": "RabbitMQ banner"}],
                login_endpoints=["/custom/signin"],
                http_probe_fn=_probe_302,
                har_out_path=har_p,
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertTrue(any(f["account"] == "guest" and f["status"] == 302 for f in r_fail["findings"]))

            # 2. All rejected -> PASS
            r_pass = sc.evaluate_aut01_default_credentials(
                "https://app.example.com",
                login_endpoints=["/custom/signin"],
                http_probe_fn=lambda ep, method="GET", headers=None, body=None: (401, {}, '{"error":"denied"}'),
                har_out_path=Path(td) / "aut01_ok.har",
            )
            self.assertEqual(r_pass["verdict"], "PASS")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 36/61: AUT-01 (Iteração SDD 167)", just_neon)

    def test_iteration168_aut02_neon_reeval(self) -> None:
        import secrets

        # 1. Weak 16-bit seed repeated 16x (64 hex chars, all 200 distinct) MUST NOT false-pass (< 64 bits)
        seen_seeds: set[str] = set()
        repeated_tokens: list[str] = []
        while len(repeated_tokens) < 200:
            s = secrets.token_hex(2)
            if s not in seen_seeds:
                seen_seeds.add(s)
                repeated_tokens.append(s * 16)
        est_weak = sc.estimate_sp800_90b_token_min_entropy(repeated_tokens)
        self.assertEqual(est_weak["uniqueTokens"], 200)
        self.assertLessEqual(est_weak["independentColumns"], 4)
        self.assertLess(est_weak["effectiveMinEntropyBits"], 64.0)

        # 2. Genuine 128-bit CSPRNG tokens still pass comfortably >= 64 bits
        strong_tokens = [secrets.token_hex(16) for _ in range(200)]
        est_strong = sc.estimate_sp800_90b_token_min_entropy(strong_tokens)
        self.assertEqual(est_strong["uniqueTokens"], 200)
        self.assertGreaterEqual(est_strong["effectiveMinEntropyBits"], 64.0)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 37/61: AUT-02 (Iteração SDD 168)", just_neon)

    def test_iteration169_aut03_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # 1. Server rotating PHPSESSID on 302 redirect login and rejecting pre-auth ID -> PASS
            def _probe_302_rot(ep: str, method: str = "GET", headers=None, body=None):
                if ep == "/":
                    return 200, {"set-cookie": "PHPSESSID=pre_php_sid_001; Path=/; HttpOnly"}, "<html></html>"
                if ep == "/login" and method == "POST":
                    return 302, {"location": "/app", "set-cookie": "PHPSESSID=post_php_sid_rotated_999; Path=/; HttpOnly"}, ""
                if ep == "/app":
                    ck = (headers or {}).get("Cookie", "")
                    if "post_php_sid_rotated_999" in ck:
                        return 200, {}, '{"ok":true}'
                    return 401, {}, '{"error":"unauthorized"}'
                return 404, {}, ""

            r_ok = sc.evaluate_aut03_session_fixation(
                "https://app.example.com",
                login_endpoint="/login",
                pre_auth_endpoints=["/"],
                protected_endpoints=["/app"],
                http_probe_fn=_probe_302_rot,
                har_out_path=Path(td) / "aut03_302.har",
            )
            self.assertEqual(r_ok["verdict"], "PASS", f"Expected PASS, got {r_ok}")
            self.assertEqual(r_ok["postToken"], "post_php_sid_rotated_999")

            # 2. Server adopting injected PHPSESSID fixation cookie -> FAIL
            def _probe_php_fix(ep: str, method: str = "GET", headers=None, body=None):
                if ep == "/login" and method == "POST":
                    return 302, {"location": "/app", "set-cookie": "PHPSESSID=new_tok_1; Path=/"}, ""
                if ep == "/app":
                    if "PHPSESSID=casa3_preauth_fixation_probe_deadbeef" in (headers or {}).get("Cookie", ""):
                        return 200, {}, '{"pwned":true}'
                    return 401, {}, ""
                return 200, {}, ""

            r_fix = sc.evaluate_aut03_session_fixation(
                "https://app.example.com",
                login_endpoint="/login",
                pre_auth_endpoints=["/"],
                protected_endpoints=["/app"],
                http_probe_fn=_probe_php_fix,
                har_out_path=Path(td) / "aut03_fix.har",
            )
            self.assertEqual(r_fix["verdict"], "FAIL")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 38/61: AUT-03 (Iteração SDD 169)", just_neon)

    def test_iteration170_aut04_neon_reeval(self) -> None:
        empty_zap = {"executed": True, "alerts": []}
        with tempfile.TemporaryDirectory() as td:
            har_p = Path(td) / "aut04.har"
            # 1. URL-encoded active token in query + client_secret in query -> FAIL + redacted HAR
            raw_tok = "sess+tok/9876543210abcdef"
            enc_tok = "sess%2Btok%2F9876543210abcdef"
            r_enc = sc.evaluate_aut04_url_token_leak(
                "https://app.example.com",
                observed_tokens={raw_tok},
                crawled_exchanges=[
                    {
                        "method": "GET",
                        "url": f"https://app.example.com/cb?state={enc_tok}&client_secret=super_oauth_sec_99",
                        "status": 200,
                        "headers": {},
                        "request_headers": {},
                        "body": "{}",
                    }
                ],
                zap_report=empty_zap,
                http_probe_fn=lambda ep, method="GET", headers=None, body=None: (404, {}, ""),
                har_out_path=har_p,
            )
            self.assertEqual(r_enc["verdict"], "FAIL")
            channels = {f["channel"] for f in r_enc["findings"]}
            self.assertIn("HAR_URL_Token_Leak", channels)
            self.assertIn("HAR_Query_Credential", channels)
            har_txt = har_p.read_text(encoding="utf-8")
            self.assertNotIn("super_oauth_sec_99", har_txt)
            self.assertIn("[REDACTED]", har_txt)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 39/61: AUT-04 (Iteração SDD 170)", just_neon)

    def test_iteration171_aut05_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # 1. Server with DELETE /api/session revoking session (returning JSON denial 200)
            #    but still accepting RFC 6749 form-urlencoded refresh_token on /oauth/token -> FAIL
            state = {"logged_out": False}

            def _probe_oauth_ref(ep: str, method: str = "GET", headers=None, body=None):
                if ep == "/rest/user/login" and method == "POST":
                    return 200, {}, json.dumps({"token": "sess_tok_a5", "refresh_token": "ref_tok_a5"})
                if ep == "/api/session" and method == "DELETE":
                    state["logged_out"] = True
                    return 204, {}, ""
                if ep == "/api/me":
                    return (200, {}, '{"authenticated": false}') if state["logged_out"] else (200, {}, '{"authenticated": true}')
                if ep == "/oauth/token" and method == "POST":
                    ct = (headers or {}).get("Content-Type", "")
                    if "x-www-form-urlencoded" not in ct:
                        return 415, {}, '{"error":"unsupported_media_type"}'
                    if b"refresh_token=ref_tok_a5" in (body or b""):
                        return 200, {}, '{"access_token":"new_tok_after_logout"}'
                    return 401, {}, '{"error":"invalid_grant"}'
                return 404, {}, ""

            r_fail = sc.evaluate_aut05_logout_invalidation(
                "https://app.example.com",
                protected_endpoints=["/api/me"],
                refresh_endpoints=["/oauth/token"],
                http_probe_fn=_probe_oauth_ref,
                har_out_path=Path(td) / "aut05_ref.har",
            )
            self.assertTrue(r_fail["serverLogoutFound"])
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertEqual([f["channel"] for f in r_fail["findings"]], ["post_logout_refresh_replay"])

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 40/61: AUT-05 (Iteração SDD 171)", just_neon)

    def test_iteration172_aut06_neon_reeval(self) -> None:
        empty_zap = {"executed": True, "alerts": []}
        with tempfile.TemporaryDirectory() as td:
            # 1. Arbitrary cookie name 'app_c' identified behaviorally (removal ends session) with SameSite=None -> FAIL
            def _probe_behav(ep: str, method: str = "GET", headers=None, body=None):
                if ep == "/api/me":
                    ck = (headers or {}).get("Cookie", "")
                    return (200, {}, '{"user":"ok"}') if "app_c=live_val_99" in ck else (401, {}, '{"error":"denied"}')
                return 200, {}, ""

            r_fail = sc.evaluate_aut06_session_cookie_flags(
                "https://app.example.com",
                protected_endpoint="/api/me",
                crawled_exchanges=[
                    {
                        "method": "POST",
                        "url": "https://app.example.com/login",
                        "status": 200,
                        "headers": {
                            "set-cookie": "app_c=live_val_99; Path=/; Secure; HttpOnly; SameSite=None, theme=dark; Path=/"
                        },
                        "body": "{}",
                    }
                ],
                http_probe_fn=_probe_behav,
                zap_report=empty_zap,
                har_out_path=Path(td) / "aut06_behav.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertEqual([f["cookieName"] for f in r_fail["findings"]], ["app_c"])

            # 2. Deletion Set-Cookie (Max-Age=0) ignored while active session cookie has all flags -> PASS
            r_ok = sc.evaluate_aut06_session_cookie_flags(
                "https://app.example.com",
                crawled_exchanges=[
                    {
                        "method": "POST",
                        "url": "https://app.example.com/login",
                        "status": 200,
                        "headers": {"set-cookie": "sid=valid123; Path=/; Secure; HttpOnly; SameSite=Lax"},
                        "body": "{}",
                    },
                    {
                        "method": "POST",
                        "url": "https://app.example.com/logout",
                        "status": 200,
                        "headers": {"set-cookie": "sid=; Path=/; Max-Age=0"},
                        "body": "{}",
                    },
                ],
                zap_report=empty_zap,
                har_out_path=Path(td) / "aut06_del.har",
            )
            self.assertEqual(r_ok["verdict"], "PASS", f"Expected PASS, got {r_ok}")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 41/61: AUT-06 (Iteração SDD 172)", just_neon)

    def test_iteration173_aut07_neon_reeval(self) -> None:
        import base64, hashlib, hmac, time

        def _b64u(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

        now = int(time.time())
        h_b64 = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
        p_b64 = _b64u(json.dumps({"sub": "u1", "iat": now, "exp": now + 3600}).encode("utf-8"))
        sig = _b64u(hmac.new(b"A" * 40, f"{h_b64}.{p_b64}".encode("utf-8"), hashlib.sha256).digest())
        valid_tok = f"{h_b64}.{p_b64}.{sig}"

        with tempfile.TemporaryDirectory() as td:
            # 1. Server accepting embedded JWK header & mixed-case alg:None -> FAIL
            def _probe_jwk_bug(ep: str, method: str = "GET", headers=None, body=None):
                if ep == "/rest/wallet/balance":
                    auth = (headers or {}).get("Authorization", "")
                    tok = auth.split(" ", 1)[1] if auth.startswith("Bearer ") else ""
                    if tok.count(".") == 2:
                        hs = tok.split(".")[0]
                        hdr = json.loads(base64.urlsafe_b64decode(hs + "=" * (-len(hs) % 4)))
                        if hdr.get("alg") == "None" or "jwk" in hdr:
                            return 200, {}, '{"balance":999}'
                    return 401, {}, '{"error":"denied"}'
                return 404, {}, ""

            r_vuln = sc.evaluate_aut07_jwt_security(
                "https://app.example.com",
                token=valid_tok,
                source_text='const tok = jwt.sign(payload, "tiny");',
                http_probe_fn=_probe_jwk_bug,
                report_out_path=Path(td) / "aut07.json",
                har_out_path=Path(td) / "aut07.har",
            )
            self.assertEqual(r_vuln["verdict"], "FAIL")
            vecs = {f["vector"] for f in r_vuln["findings"]}
            self.assertIn("unsigned_alg_none_mixedcase", vecs)
            self.assertIn("embedded_jwk_key_substitution", vecs)
            self.assertIn("weak_hs256_key", vecs)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 42/61: AUT-07 (Iteração SDD 173)", just_neon)

    def test_iteration174_aut08_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # 1. Hyphenated Luhn-valid PAN + nested JSON refresh_token under benign key + case-insensitive IdP email -> FAIL
            snap_bad = {
                "before": {
                    "href": "https://app.example.com/profile",
                    "localStorage": {
                        "checkout_draft": "card=4532-0151-1283-0366",
                        "redux_state": '{"auth":{"refresh_token":"opaque_rt_99887766"}}',
                        "ui_cache": "logged in as alice.smith@corp.example",
                    },
                    "sessionStorage": {},
                    "nonHttpOnlyCookies": "",
                    "indexedDB": [],
                },
                "after": {
                    "href": "https://app.example.com/",
                    "localStorage": {},
                    "sessionStorage": {},
                    "nonHttpOnlyCookies": "",
                    "indexedDB": [],
                },
            }
            r_bad = sc.evaluate_aut08_client_storage(
                "https://app.example.com",
                idp_profile_values=["Alice.Smith@corp.example"],
                snapshot_override=snap_bad,
                report_out_path=Path(td) / "aut08_bad.json",
                har_out_path=Path(td) / "aut08_bad.har",
            )
            self.assertEqual(r_bad["verdict"], "FAIL")
            all_reasons = " ".join(r for f in r_bad["findings"] for r in f["reasons"])
            self.assertIn("Luhn_PAN", all_reasons)
            self.assertIn("nested_auth_key(refresh_token)", all_reasons)
            self.assertIn("idp_profile(", all_reasons)

            # 2. Clean benign preferences before & after logout -> PASS
            snap_ok = {
                "before": {
                    "href": "https://app.example.com/",
                    "localStorage": {"theme": "dark", "locale": "pt-BR"},
                    "sessionStorage": {},
                    "nonHttpOnlyCookies": "language=pt-BR",
                    "indexedDB": [],
                },
                "after": {
                    "href": "https://app.example.com/",
                    "localStorage": {"theme": "dark"},
                    "sessionStorage": {},
                    "nonHttpOnlyCookies": "language=pt-BR",
                    "indexedDB": [],
                },
            }
            r_ok = sc.evaluate_aut08_client_storage(
                "https://app.example.com",
                idp_profile_values=["Alice.Smith@corp.example"],
                snapshot_override=snap_ok,
                report_out_path=Path(td) / "aut08_ok.json",
                har_out_path=Path(td) / "aut08_ok.har",
            )
            self.assertEqual(r_ok["verdict"], "PASS", f"Expected PASS, got {r_ok}")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 43/61: AUT-08 (Iteração SDD 174)", just_neon)

    def test_iteration175_azi01_neon_reeval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # 1. Benign non-session cookie with SameSite=None + session cookie 'sid' with SameSite=Strict + strict CSRF -> PASS
            state = {"displayName": "orig"}

            def _probe_csrf(ep: str, method: str = "GET", headers=None, body=None):
                ck = (headers or {}).get("Cookie", "")
                if ep == "/settings" and method == "GET":
                    csrf = "csrf_a" if "sid=tokA" in ck else "csrf_b"
                    return (
                        200,
                        {
                            "set-cookie": "sid=tokA; Path=/; HttpOnly; SameSite=Strict, analytics_id=123; Path=/; SameSite=None; Secure",
                            "x-csrf-token": csrf,
                        },
                        f'<html>displayName={state["displayName"]}<input name="_csrf" value="{csrf}"></html>',
                    )
                if ep == "/settings" and method == "POST":
                    tok = (headers or {}).get("X-CSRF-Token", "")
                    if "sid=tokA" in ck and tok == "csrf_a":
                        return 200, {}, '{"ok":true}'
                    return 403, {}, '{"error":"bad csrf"}'
                return 404, {}, ""

            r_ok = sc.evaluate_azi01_anti_csrf(
                "https://app.example.com",
                session_a_token="tokA",
                session_b_token="tokB",
                state_endpoint="/settings",
                cookie_name="sid",
                state_field="displayName",
                http_probe_fn=_probe_csrf,
                har_out_path=Path(td) / "azi01_ok.har",
            )
            self.assertEqual(r_ok["verdict"], "PASS", f"Expected PASS, got {r_ok}")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 44/61: AZI-01 (Iteração SDD 175)", just_neon)

    def test_iteration176_azi02_neon_reeval(self) -> None:
        import urllib.parse

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            # 1. application/xhtml+xml unescaped reflection on custom reflected_endpoints -> FAIL
            def _probe_xhtml(ep: str, method: str = "GET", headers=None, body=None):
                q = urllib.parse.unquote(ep.split("q=", 1)[1]) if "q=" in ep else ""
                if "/xhtml-search" in ep:
                    return 200, {"content-type": "application/xhtml+xml"}, f"<html><body>{q}</body></html>"
                return 200, {"content-type": "application/json"}, json.dumps({"echo": q})

            r_xhtml = sc.evaluate_azi02_xss(
                "https://app.example.com",
                reflected_endpoints=["/xhtml-search?q={p}", "/json-search?q={p}"],
                http_probe_fn=_probe_xhtml,
                run_zap=False,
                run_browser=False,
                report_out_path=tdp / "azi02_xhtml.json",
                har_out_path=tdp / "azi02_xhtml.har",
            )
            self.assertEqual(r_xhtml["verdict"], "FAIL")
            self.assertEqual(len(r_xhtml["findings"]), 1)
            self.assertIn("/xhtml-search", r_xhtml["findings"][0]["url"])
            self.assertEqual(r_xhtml["inconclusiveCandidates"], [])

            # 2. JSON-only echo does NOT false-positive as HTML reflection -> PASS
            r_json = sc.evaluate_azi02_xss(
                "https://app.example.com",
                reflected_endpoints=["/json-search?q={p}"],
                http_probe_fn=_probe_xhtml,
                run_zap=False,
                run_browser=False,
                report_out_path=tdp / "azi02_json.json",
                har_out_path=tdp / "azi02_json.har",
            )
            self.assertEqual(r_json["verdict"], "PASS")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 45/61: AZI-02 (Iteração SDD 176)", just_neon)

    def test_iteration177_azi03_neon_reeval(self) -> None:
        # 1. _count_json_records handles standard REST envelopes (results, records, rows, users)
        self.assertEqual(sc._count_json_records(200, '{"results":[1,2,3]}'), 3)
        self.assertEqual(sc._count_json_records(200, '{"records":[{"id":1},{"id":2}]}'), 2)
        self.assertEqual(sc._count_json_records(200, '{"rows":[]}'), 0)

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            # 2. GET query-string filter alteration detected via differential record count -> FAIL
            def _probe_get_nosql(ep: str, method: str = "GET", headers=None, body=None, follow_redirects=True):
                if ep.startswith("/api/items"):
                    if "%5B%24ne%5D" in ep or "[$ne]" in ep:
                        return 200, {"content-type": "application/json"}, '{"results":[{"id":1},{"id":2}]}'
                    return 200, {"content-type": "application/json"}, '{"results":[]}'
                return 404, {}, '{"error":"not found"}'

            r_fail = sc.evaluate_azi03_sqli_nosql(
                "https://app.example.com",
                nosql_query_targets=[{"path": "/api/items", "param": "filter", "method": "GET"}],
                http_probe_fn=_probe_get_nosql,
                run_sqlmap=False,
                run_zap=False,
                report_out_path=tdp / "azi03.json",
                har_out_path=tdp / "azi03.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertTrue(any(f["vulnType"] == "NoSQL_Operator_Result_Altered_$ne" for f in r_fail["findings"]))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 46/61: AZI-03 (Iteração SDD 177)", just_neon)

    def test_iteration178_azi04_neon_reeval(self) -> None:
        """SDD 178 (AZI-04): DNS compression pointer safety, oob_wait_sec & Windows principal marker."""
        # Standard DNS query header (12 bytes) + label "cb" + compression pointer 0xC0 0x0C
        pkt_compressed = b"\x00" * 12 + b"\x02cb\xc0\x0c"
        self.assertEqual(sc._parse_dns_qname(pkt_compressed), "cb")

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            def _probe_win_marker(url, method="GET", headers=None, body=None, timeout=5):
                return 200, {"content-type": "text/plain"}, "nt authority\\system\r\n"

            r_fail = sc.evaluate_azi04_cmd_injection(
                "https://app.example.com",
                param_targets=[("GET", "/api/ping?host={p}", "query:host")],
                http_probe_fn=_probe_win_marker,
                run_zap=False,
                oob_wait_sec=0.0,
                report_out_path=tdp / "azi04-fail.json",
                har_out_path=tdp / "azi04-fail.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertTrue(any("nt authority\\system" in f["evidence"].lower() for f in r_fail["findings"]))

            def _probe_safe(url, method="GET", headers=None, body=None, timeout=5):
                return 200, {"content-type": "application/json"}, '{"status":"ok"}'

            r_pass = sc.evaluate_azi04_cmd_injection(
                "https://app.example.com",
                param_targets=[("GET", "/api/ping?host={p}", "query:host")],
                http_probe_fn=_probe_safe,
                run_zap=False,
                oob_wait_sec=0.0,
                report_out_path=tdp / "azi04-pass.json",
                har_out_path=tdp / "azi04-pass.har",
            )
            self.assertEqual(r_pass["verdict"], "PASS")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 47/61: AZI-04 (Iteração SDD 178)", just_neon)

    def test_iteration179_azi05_neon_reeval(self) -> None:
        """SDD 179 (AZI-05): Windows win.ini marker, backslash vector & per-target RFI attribution."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            def _probe_win_ini(url, method="GET", headers=None, body=None, timeout=5):
                if "win.ini" in url.lower():
                    return 200, {"content-type": "text/plain"}, "; for 16-bit app support\r\n[extensions]\r\n"
                return 404, {"content-type": "text/plain"}, "not found"

            r_fail = sc.evaluate_azi05_lfi_rfi(
                "https://app.example.com",
                param_targets=[("doc", "/api/doc?file={p}")],
                http_probe_fn=_probe_win_ini,
                run_zap=False,
                run_rfi=False,
                report_out_path=tdp / "azi05-win.json",
                har_out_path=tdp / "azi05-win.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertTrue(any(f["form"] == "doc_win_backslash" for f in r_fail["findings"]))

            # Verify per-target RFI isolation: only /vuln triggers OOB fetch, /safe returns 200 cleanly
            def _probe_rfi_isolated(url, method="GET", headers=None, body=None, timeout=5):
                if "/vuln?" in url:
                    import urllib.parse, urllib.request
                    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
                    cb_url = qs.get("tpl", [""])[0]
                    if cb_url.startswith("http://127.0.0.1:"):
                        urllib.request.urlopen(cb_url, timeout=2).read()
                    return 200, {"content-type": "text/html"}, "loaded"
                return 200, {"content-type": "text/html"}, "safe-ok"

            r_rfi = sc.evaluate_azi05_lfi_rfi(
                "https://app.example.com",
                param_targets=[],
                rfi_targets=["/vuln?tpl={p}", "/safe?tpl={p}"],
                http_probe_fn=_probe_rfi_isolated,
                run_zap=False,
                run_rfi=True,
                report_out_path=tdp / "azi05-rfi.json",
                har_out_path=tdp / "azi05-rfi.har",
            )
            self.assertEqual(r_rfi["verdict"], "FAIL")
            urls_flagged = [f["url"] for f in r_rfi["findings"]]
            self.assertIn("https://app.example.com/vuln", urls_flagged)
            self.assertNotIn("https://app.example.com/safe", urls_flagged)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 48/61: AZI-05 (Iteração SDD 179)", just_neon)

    def test_iteration180_azi06_neon_reeval(self) -> None:
        """SDD 180 (AZI-06): Backslash URL normalization, quoted meta-refresh & unsafe redirect schemes."""
        self.assertEqual(sc._parse_redirect_scheme_host("/\\evil.example.com/path"), ("", "evil.example.com"))
        self.assertEqual(sc._parse_redirect_scheme_host("\\\\evil.example.com"), ("", "evil.example.com"))
        self.assertEqual(sc._parse_redirect_scheme_host("javascript:alert(1)"), ("javascript", ""))
        self.assertEqual(
            sc._extract_redirect_target(200, {}, "<meta http-equiv='refresh' content=\"0; url='https://evil.example.com/p'\">"),
            "https://evil.example.com/p",
        )

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            def _probe_backslash_redir(url, method="GET", headers=None, body=None, timeout=5, follow_redirects=False):
                if "backslash" in url:
                    return 302, {"location": "/\\evil.example.com/login"}, ""
                if "jsscheme" in url:
                    return 302, {"location": "javascript:void(0)"}, ""
                return 302, {"location": "/dashboard"}, ""

            r_fail = sc.evaluate_azi06_open_redirect_hpp(
                "https://app.example.com",
                redirect_targets=[
                    ("backslash_case", "/go?to=backslash"),
                    ("js_case", "/go?to=jsscheme"),
                ],
                hpp_targets=[],
                http_probe_fn=_probe_backslash_redir,
                run_zap=False,
                report_out_path=tdp / "azi06.json",
                har_out_path=tdp / "azi06.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            kinds = {f["kind"] for f in r_fail["findings"]}
            self.assertIn("OpenRedirect_backslash_case", kinds)
            self.assertIn("OpenRedirect_js_case_unsafe_scheme", kinds)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 49/61: AZI-06 (Iteração SDD 180)", just_neon)

    def test_iteration181_oau01_neon_reeval(self) -> None:
        """SDD 181 (OAU-01): Space-separated hybrid response_type & JS/JSON responseType/grantType."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            r_hybrid = sc.evaluate_oau01_grant_type(
                "https://app.example.com",
                oauth_sources=[
                    ("auth.ts", "const url = 'https://idp.example.com/authorize?response_type=code id_token&client_id=abc';"),
                    ("cfg.ts", 'const cfg = { responseType: "token", grantType: "password" };'),
                ],
                run_semgrep=False,
                report_out_path=tdp / "oau01-fail.json",
                har_out_path=tdp / "oau01-fail.har",
            )
            self.assertEqual(r_hybrid["verdict"], "FAIL")
            viols = {f["grantViolation"] for f in r_hybrid["findings"]}
            self.assertIn("response_type=code id_token", viols)
            self.assertIn("response_type=token", viols)
            self.assertIn("grant_type=password", viols)

            r_pass = sc.evaluate_oau01_grant_type(
                "https://app.example.com",
                oauth_sources=[("auth.ts", "const url = 'https://idp.example.com/authorize?response_type=code&client_id=abc';")],
                run_semgrep=False,
                report_out_path=tdp / "oau01-pass.json",
                har_out_path=tdp / "oau01-pass.har",
            )
            self.assertEqual(r_pass["verdict"], "PASS")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 50/61: OAU-01 (Iteração SDD 181)", just_neon)

    def test_iteration182_oau02_neon_reeval(self) -> None:
        """SDD 182 (OAU-02): RFC 7636 code_verifier length/charset & code_challenge base64url bounds."""
        import base64, hashlib, http.server, threading

        class _IdpHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://app.example.com/cb?code=ok")
                self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"access_token":"ok"}')

            def log_message(self, *args):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _IdpHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as td:
                tdp = Path(td)
                short_ver = "short_verifier_under_43_chars"
                derived_cc = base64.urlsafe_b64encode(hashlib.sha256(short_ver.encode()).digest()).decode().rstrip("=")
                r_fail = sc.evaluate_oau02_pkce(
                    f"http://127.0.0.1:{port}",
                    oauth_flow_requests=[
                        {"method": "GET", "url": f"http://127.0.0.1:{port}/authorize?response_type=code&code_challenge={derived_cc}&code_challenge_method=S256"},
                        {"method": "POST", "url": f"http://127.0.0.1:{port}/token", "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": f"grant_type=authorization_code&code=ok&code_verifier={short_ver}"},
                    ],
                    run_semgrep=False,
                    report_out_path=tdp / "oau02-fail.json",
                    har_out_path=tdp / "oau02-fail.har",
                )
                self.assertEqual(r_fail["verdict"], "FAIL")
                self.assertTrue(any("RFC 7636 §4.1" in f["detail"] for f in r_fail["findings"]))

                valid_ver = "A" * 64
                valid_cc = base64.urlsafe_b64encode(hashlib.sha256(valid_ver.encode()).digest()).decode().rstrip("=")
                r_pass = sc.evaluate_oau02_pkce(
                    f"http://127.0.0.1:{port}",
                    oauth_flow_requests=[
                        {"method": "GET", "url": f"http://127.0.0.1:{port}/authorize?response_type=code&code_challenge={valid_cc}&code_challenge_method=S256"},
                        {"method": "POST", "url": f"http://127.0.0.1:{port}/token", "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": f"grant_type=authorization_code&code=ok&code_verifier={valid_ver}"},
                    ],
                    run_semgrep=False,
                    report_out_path=tdp / "oau02-pass.json",
                    har_out_path=tdp / "oau02-pass.har",
                )
                self.assertEqual(r_pass["verdict"], "PASS")
        finally:
            srv.shutdown()
            srv.server_close()

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 51/61: OAU-02 (Iteração SDD 182)", just_neon)

    def test_iteration183_oau03_neon_reeval(self) -> None:
        """SDD 183 (OAU-03): Surface-scoped loopback http: rule & backslash callback redirect detection."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            def _probe_cb(url, method="GET", headers=None, body=None, timeout=5, follow_redirects=False):
                if "/cb?next=" in url:
                    return 302, {"location": "/\\oau03-evil.example.com/p"}, ""
                return 200, {}, "ok"

            r_web_fail = sc.evaluate_oau03_redirect_uris(
                "https://app.example.com",
                oauth_sources=[("auth.ts", "const u = 'https://idp.example.com/auth?redirect_uri=http://localhost:8080/cb';")],
                callback_paths=["/cb"],
                surfaces=["Web_Application"],
                http_probe_fn=_probe_cb,
                report_out_path=tdp / "oau03-web.json",
                har_out_path=tdp / "oau03-web.har",
            )
            self.assertEqual(r_web_fail["verdict"], "FAIL")
            kinds = {f["kind"] for f in r_web_fail["findings"]}
            self.assertIn("Web_Surface_Loopback_HTTP_Redirect_URI", kinds)
            self.assertIn("Callback_Open_Redirect_direct", kinds)

            r_mobile_pass = sc.evaluate_oau03_redirect_uris(
                "https://app.example.com",
                oauth_sources=[("auth.ts", "const u = 'https://idp.example.com/auth?redirect_uri=http://127.0.0.1:8080/cb';")],
                callback_paths=[],
                surfaces=["Mobile"],
                http_probe_fn=lambda *a, **kw: (200, {}, "ok"),
                report_out_path=tdp / "oau03-mob.json",
                har_out_path=tdp / "oau03-mob.har",
            )
            self.assertEqual(r_mobile_pass["verdict"], "PASS")
            self.assertEqual(r_mobile_pass["loopbackHttpCount"], 1)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 52/61: OAU-03 (Iteração SDD 183)", just_neon)

    def test_iteration184_oau04_neon_reeval(self) -> None:
        """SDD 184 (OAU-04): Constant-prefix state entropy guard & generic session cookie callback detection."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            idx_box = {"n": 0}
            fixed_prefix = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

            def _probe_oau04(url, method="GET", headers=None, body=None, timeout=5, follow_redirects=False):
                if url.endswith("/oauth/authorize"):
                    idx_box["n"] += 1
                    st_val = f"{fixed_prefix}_{idx_box['n']:04d}"
                    return 302, {"location": f"https://idp.example.com/auth?state={st_val}"}, ""
                if "/cb?" in url and "state=" not in url:
                    return 302, {"set-cookie": "connect.sid=live_sess_123; HttpOnly; Secure", "location": "/home"}, ""
                return 403, {}, "denied"

            r_fail = sc.evaluate_oau04_state_nonce(
                "https://app.example.com",
                authorize_paths=["/oauth/authorize"],
                callback_paths=["/cb"],
                sample_count=20,
                http_probe_fn=_probe_oau04,
                run_semgrep=False,
                report_out_path=tdp / "oau04.json",
                har_out_path=tdp / "oau04.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            kinds = {f["kind"] for f in r_fail["findings"]}
            self.assertIn("Insufficient_State_MinEntropy", kinds)
            self.assertIn("Callback_Accepted_state_omitted", kinds)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 53/61: OAU-04 (Iteração SDD 184)", just_neon)

    def test_iteration185_oau05_neon_reeval(self) -> None:
        """SDD 185 (OAU-05): Windows WebView2, modern Flutter webview packages & Electron HAR UA detection."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "AuthWindow.cs").write_text(
                "using Microsoft.Web.WebView2;\nvar url = \"https://idp.example.com/authorize?client_id=1&response_type=code\";\n",
                encoding="utf-8",
            )
            (tdp / "login_screen.dart").write_text(
                "import 'package:webview_flutter/webview_flutter.dart';\nfinal authUrl = 'https://idp.example.com/oauth2/authorize';\n",
                encoding="utf-8",
            )
            har_electron = [
                {
                    "request": {
                        "url": "https://idp.example.com/oauth2/authorize?client_id=desk&response_type=code",
                        "headers": [{"name": "User-Agent", "value": "Mozilla/5.0 MyApp/1.0 Chrome/120.0 Electron/28.1 Safari/537.36"}],
                    }
                }
            ]
            r_fail = sc.evaluate_oau05_system_browser(
                "https://app.example.com",
                repo=tdp,
                har_entries=har_electron,
                run_semgrep=False,
                report_out_path=tdp / "oau05.json",
                har_out_path=tdp / "oau05.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            kinds = {f["kind"] for f in r_fail["findings"]}
            self.assertIn("Windows_WebView2", kinds)
            self.assertIn("Hybrid_InAppBrowser", kinds)
            self.assertIn("HAR_Embedded_WebView_UserAgent", kinds)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 54/61: OAU-05 (Iteração SDD 185)", just_neon)

    def test_iteration186_oau06_neon_reeval(self) -> None:
        """SDD 186 (OAU-06): HAR postData client_secret & Authorization: Basic on public-client /token."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            har_entries = [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://idp.example.com/oauth2/token",
                        "headers": [{"name": "Authorization", "value": "Basic Y2xpZW50OnNlY3JldA=="}],
                        "postData": {"text": "grant_type=authorization_code&code=abc&client_secret=synthetic_secret_val"},
                    }
                }
            ]
            r_fail = sc.evaluate_oau06_client_secrets(
                "https://app.example.com",
                repo=tdp,
                har_entries=har_entries,
                run_semgrep=False,
                report_out_path=tdp / "oau06.json",
                har_out_path=tdp / "oau06.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            kinds = {f["kind"] for f in r_fail["findings"]}
            self.assertIn("HAR_Token_Request_Client_Secret", kinds)
            self.assertIn("HAR_Token_Request_Basic_Client_Auth", kinds)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 55/61: OAU-06 (Iteração SDD 186)", just_neon)

    def test_iteration187_oau07_neon_reeval(self) -> None:
        """SDD 187 (OAU-07): Multi Set-Cookie splitting, Max-Age=0 filter & benign-name IndexedDB JWT check."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJlMTIz"

            def _probe_multi_cookie(url, method="GET", headers=None, body=None, timeout=5, follow_redirects=False):
                return (
                    200,
                    {"set-cookie": "theme=dark; Path=/, refresh_token=tok_abc123; Path=/; HttpOnly, old_token=; Max-Age=0"},
                    "ok",
                )

            r_fail = sc.evaluate_oau07_token_storage(
                "https://app.example.com",
                repo=tdp,
                storage_snapshot={"before": {"localStorage": {}, "sessionStorage": {}, "indexedDB": [{"name": "app_cache", "items": [fake_jwt]}], "nonHttpOnlyCookies": ""}},
                observed_token=fake_jwt,
                login_paths=["/oauth/callback"],
                http_probe_fn=_probe_multi_cookie,
                run_semgrep=False,
                report_out_path=tdp / "oau07.json",
                har_out_path=tdp / "oau07.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            kinds = {f["kind"] for f in r_fail["findings"]}
            locs = {f["location"] for f in r_fail["findings"]}
            self.assertIn("Browser_IndexedDB_Token", kinds)
            self.assertIn("Cookie_Missing_HttpOnly_Or_Secure", kinds)
            self.assertIn("https://app.example.com/oauth/callback#cookie:refresh_token", locs)
            self.assertNotIn("https://app.example.com/oauth/callback#cookie:old_token", locs)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 56/61: OAU-07 (Iteração SDD 187)", just_neon)

    def test_iteration188_oau08_neon_reeval(self) -> None:
        """SDD 188 (OAU-08): Opaque URL fragment, POST form-body access_token & DPoP Authorization PASS."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            har_bad = [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/v1/profile#access_token=opaque_frag_tok_123",
                        "headers": [],
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/v1/orders",
                        "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                        "postData": {"text": "access_token=opaque_body_tok_456&item=1"},
                    }
                },
            ]
            r_fail = sc.evaluate_oau08_token_transport(
                "https://api.example.com",
                har_entries_in=har_bad,
                run_semgrep=False,
                report_out_path=tdp / "oau08-fail.json",
                har_out_path=tdp / "oau08-fail.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            kinds = {f["kind"] for f in r_fail["findings"]}
            self.assertIn("HAR_Fragment_Access_Token", kinds)
            self.assertIn("HAR_Body_Form_Access_Token", kinds)

            har_good = [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/v1/profile",
                        "headers": [{"name": "Authorization", "value": "DPoP valid_bound_tok"}],
                    }
                }
            ]
            r_pass = sc.evaluate_oau08_token_transport(
                "https://api.example.com",
                har_entries_in=har_good,
                run_semgrep=False,
                report_out_path=tdp / "oau08-pass.json",
                har_out_path=tdp / "oau08-pass.har",
            )
            self.assertEqual(r_pass["verdict"], "PASS")
            self.assertEqual(r_pass["bearerHeaderRequests"], 1)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 57/61: OAU-08 (Iteração SDD 188)", just_neon)

    def test_iteration189_oau09_neon_reeval(self) -> None:
        """SDD 189 (OAU-09): Mixed-case alg:None, future nbf claim & L25 HTTP 200 JSON denial guard."""
        import base64, json as _json

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            valid_tok = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1MSIsImV4cCI6NDAwMDAwMDAwMH0.sigvalid"

            def _probe_oau09(url, method="GET", headers=None, body=None, timeout=5, follow_redirects=False):
                auth = (headers or {}).get("Authorization", "")
                tok = auth.replace("Bearer ", "").strip()
                if not tok or "." not in tok:
                    return 404, {}, ""
                if tok == valid_tok:
                    return 200, {"content-type": "application/json"}, '{"balance":100}'
                hdr_b64 = tok.split(".")[0]
                hdr_obj = _json.loads(base64.urlsafe_b64decode(hdr_b64 + "=" * (-len(hdr_b64) % 4)).decode())
                if hdr_obj.get("alg") == "None":
                    return 200, {"content-type": "application/json"}, '{"balance":100}'
                # Soft JSON denial envelope on HTTP 200 (must count as DENIED per Test Guide L25)
                return 200, {"content-type": "application/json"}, '{"error":"unauthorized","message":"invalid token"}'

            r_fail = sc.evaluate_oau09_token_validation(
                "https://api.example.com",
                observed_token=valid_tok,
                endpoints=["/api/balance"],
                http_probe_fn=_probe_oau09,
                run_semgrep=False,
                report_out_path=tdp / "oau09.json",
                har_out_path=tdp / "oau09.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertEqual(r_fail["acceptedVectors"], ["unsigned_alg_none_mixedcase"])
            self.assertIn("nbf_future_claim", r_fail["rejectedVectors"])

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 58/61: OAU-09 (Iteração SDD 189)", just_neon)

    def test_iteration190_whk01_neon_reeval(self) -> None:
        """SDD 190 (WHK-01): SSLv3 legacy detection & malformed HTTPS redirect rejection."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            def _http_bad_redir(url, method="POST", headers=None, body=None, follow_redirects=False):
                return 301, {"location": "https:///relative-no-host"}, ""

            r_fail = sc.evaluate_whk01_tls_enforcement(
                "https://hooks.example.com",
                receivers=["https://hooks.example.com/webhook"],
                http_probe_fn=_http_bad_redir,
                tls_matrix_fn=lambda h, p: {"SSLv3": "offered", "TLS 1.0": "not offered", "TLS 1.1": "not offered", "TLS 1.2": "offered", "TLS 1.3": "offered"},
                run_testssl=False,
                run_semgrep=False,
                report_out_path=tdp / "whk01-fail.json",
                har_out_path=tdp / "whk01-fail.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            kinds = {f["kind"] for f in r_fail["findings"]}
            self.assertIn("WHK01_NonHTTPS_Redirect", kinds)
            self.assertIn("WHK01_Legacy_TLS_Offered", kinds)

            r_pass = sc.evaluate_whk01_tls_enforcement(
                "https://hooks.example.com",
                receivers=["https://hooks.example.com/webhook"],
                http_probe_fn=lambda *a, **kw: (308, {"location": "https://hooks.example.com/webhook"}, ""),
                tls_matrix_fn=lambda h, p: {"SSLv2": "not offered", "SSLv3": "not offered", "TLS 1.0": "not offered", "TLS 1.1": "not offered", "TLS 1.2": "offered", "TLS 1.3": "offered"},
                run_testssl=False,
                run_semgrep=False,
                report_out_path=tdp / "whk01-pass.json",
                har_out_path=tdp / "whk01-pass.har",
            )
            self.assertEqual(r_pass["verdict"], "PASS")

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 59/61: WHK-01 (Iteração SDD 190)", just_neon)

    def test_iteration191_whk02_neon_reeval(self) -> None:
        """SDD 191 (WHK-02): Standard Webhooks headers, PHP/Ruby/.NET constant-time APIs & L25 JSON denial."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            seen_sw_headers: list[str] = []

            def _http_l25_deny(url, method="POST", headers=None, body=None, follow_redirects=False):
                if headers and "webhook-signature" in headers:
                    seen_sw_headers.append(headers["webhook-signature"])
                return 200, {"content-type": "application/json"}, '{"ok":false,"error":"invalid signature"}'

            r_pass = sc.evaluate_whk02_signature_verification(
                "https://hooks.example.com",
                receivers=["https://hooks.example.com/webhook"],
                webhook_files={"handler.php": "$sig = hash_hmac('sha256', $body, $secret); hash_equals($sig, $hdr);"},
                http_probe_fn=_http_l25_deny,
                run_semgrep=False,
                report_out_path=tdp / "whk02-pass.json",
                har_out_path=tdp / "whk02-pass.har",
            )
            self.assertEqual(r_pass["verdict"], "PASS")
            self.assertEqual(r_pass["clauses"]["timing_safe_compare"], "PASS")
            self.assertEqual(len(seen_sw_headers), 3)
            self.assertTrue(all(h.startswith("v1,") for h in seen_sw_headers))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 60/61: WHK-02 (Iteração SDD 191)", just_neon)

    def test_iteration192_whk03_neon_reeval(self) -> None:
        """SDD 192 (WHK-03): fc00::/7 ULA, ::ffff:127.0.0.1 v4-mapped IPv6, webhook_signing_key & L25 guard."""
        import json as _json

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            seen_urls: list[str] = []

            def _reg_probe(url, method="POST", headers=None, body=None, follow_redirects=False):
                payload = _json.loads((body or b"{}").decode("utf-8"))
                u = str(payload.get("url") or "")
                seen_urls.append(u)
                if "fc00::1" in u or "::ffff:127.0.0.1" in u:
                    return 201, {"content-type": "application/json"}, '{"registered":true}'
                return 200, {"content-type": "application/json"}, '{"ok":false,"error":"forbidden internal address"}'

            r_fail = sc.evaluate_whk03_ssrf_protection(
                "https://hooks.example.com",
                callback_endpoints=["https://hooks.example.com/api/webhooks/register"],
                webhook_files={"cfg.ts": 'const webhook_signing_key = "synthetic_key_value_9988776655";'},
                http_probe_fn=_reg_probe,
                run_gitleaks=False,
                run_semgrep=False,
                report_out_path=tdp / "whk03-fail.json",
                har_out_path=tdp / "whk03-fail.har",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertEqual(r_fail["probesRun"], 13)
            kinds = {f["kind"] for f in r_fail["findings"]}
            self.assertIn("WHK03_SSRF_Accepted_Restricted_URL_ula_ipv6_fc00", kinds)
            self.assertIn("WHK03_SSRF_Accepted_Restricted_URL_ipv4_mapped_ipv6_loopback", kinds)
            self.assertIn("WHK03_Hardcoded_Signing_Secret", kinds)
            # Soft JSON denial on HTTP 200 for 10.0.0.1 must NOT false-positive
            self.assertNotIn("WHK03_SSRF_Accepted_Restricted_URL_private_rfc1918_10", kinds)
            self.assertTrue(any("[fc00::1]" in u for u in seen_urls))

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 61/61: WHK-03 (Iteração SDD 192)", just_neon)

    def test_iteration193_scan_progress_api_and_ui(self) -> None:
        """SDD 193: Live scan progress callback, async /api/scan/start + /api/scan/status & UI panel."""
        import http.server
        import json as _json
        import threading
        import time as _time
        import urllib.request
        from casa_audit.server import CasaAssessmentHandler

        # 1. Verify progress_cb fires stage + control events across all 61 AL1 controls
        events: list[dict] = []
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "package.json").write_text('{"name":"demo","version":"1.0.0"}', encoding="utf-8")
            res = sc.run_automated_al1_scan(
                target_url="",
                repo_path=str(tdp),
                surfaces=["Web_Application"],
                progress_cb=events.append,
            )
            self.assertEqual(len(res), 61)
            stage_domains = {e["domain"] for e in events if e.get("type") == "stage"}
            ctrl_ids = {e["control_id"] for e in events if e.get("type") == "control"}
            self.assertTrue({"SCA", "SAST", "FINAL"}.issubset(stage_domains))
            self.assertEqual(len(ctrl_ids), 61)

            # 2. Verify async HTTP endpoints POST /api/scan/start (202) -> GET /api/scan/status (200)
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CasaAssessmentHandler)
            port = srv.server_address[1]
            t_srv = threading.Thread(target=srv.serve_forever, daemon=True)
            t_srv.start()
            try:
                req_start = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/scan/start",
                    data=_json.dumps({"target_url": "", "repo_path": str(tdp), "surfaces": ["Web_Application"]}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req_start, timeout=10) as resp_s:
                    self.assertEqual(resp_s.status, 202)
                    started = _json.loads(resp_s.read().decode("utf-8"))
                scan_id = started["scan_id"]
                self.assertTrue(scan_id)
                self.assertEqual(started["progress"]["total"], 61)

                final_snap = None
                for _ in range(120):
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/scan/status?id={scan_id}", timeout=10) as resp_p:
                        self.assertEqual(resp_p.status, 200)
                        snap = _json.loads(resp_p.read().decode("utf-8"))
                    if snap["status"] == "completed":
                        final_snap = snap
                        break
                    _time.sleep(0.25)

                self.assertIsNotNone(final_snap, "Async scan job did not complete within timeout")
                self.assertEqual(final_snap["count"], 61)
                self.assertEqual(final_snap["progress"]["completed"], 61)
                self.assertEqual(final_snap["progress"]["percent"], 100)
                self.assertEqual(final_snap["progress"]["domain_order"], ["SCA", "SAST", "TLS", "CFG", "AUT", "AZI", "OAU", "WHK"])
                self.assertEqual(final_snap["progress"]["domains"]["SCA"]["status"], "done")
            finally:
                srv.shutdown()
                srv.server_close()

        # 3. Verify frontend UI markup, styles, and polling logic exist
        html_txt = (ROOT_DIR / "casa-assessment" / "frontend" / "assess.html").read_text(encoding="utf-8")
        js_txt = (ROOT_DIR / "casa-assessment" / "frontend" / "app.js").read_text(encoding="utf-8")
        css_txt = (ROOT_DIR / "casa-assessment" / "frontend" / "styles.css").read_text(encoding="utf-8")
        self.assertIn('id="scan-progress-panel"', html_txt)
        self.assertIn('id="scan-domain-grid"', html_txt)
        self.assertIn("/api/scan/start", js_txt)
        self.assertIn("/api/scan/status?id=", js_txt)
        self.assertIn(".scan-dom-chip.is-running", css_txt)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("ITERAÇÃO SDD 193", just_neon)

    def test_iteration194_app_registry_and_locked_meta(self) -> None:
        """SDD 194: Application pre-registration/selection gate, locked Assessor/Target & auto scan date."""
        import http.server
        import json as _json
        import threading
        import urllib.error
        import urllib.request
        import casa_audit.server as srv_mod

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            orig_store = srv_mod.APPS_STORE_PATH
            srv_mod.APPS_STORE_PATH = tdp / "applications.json"
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), srv_mod.CasaAssessmentHandler)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                # 1. Empty registry initially
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/applications", timeout=5) as r0:
                    self.assertEqual(r0.status, 200)
                    d0 = _json.loads(r0.read().decode("utf-8"))
                self.assertEqual(d0["applications"], [])

                # 2. Validation rejects missing assessor
                bad_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/applications",
                    data=_json.dumps({"org": "Juice Shop", "assessor": "", "target": "AL1"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx_err:
                    urllib.request.urlopen(bad_req, timeout=5)
                self.assertEqual(ctx_err.exception.code, 400)

                # 3. Create application -> 201
                create_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/applications",
                    data=_json.dumps(
                        {
                            "org": "OWASP Juice Shop",
                            "assessor": "Felipe Lab",
                            "target": "AL1",
                            "targetUrl": "http://localhost:3000",
                            "repoPath": "/tmp/juice",
                            "surfaces": ["Web_Application"],
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(create_req, timeout=5) as r1:
                    self.assertEqual(r1.status, 201)
                    d1 = _json.loads(r1.read().decode("utf-8"))
                app_id = d1["application"]["id"]
                self.assertEqual(d1["application"]["assessor"], "Felipe Lab")
                self.assertEqual(d1["application"]["target"], "AL1")
                self.assertEqual(d1["application"]["date"], "")

                # 4. Update application (assessor + target + auto scan date) -> 200
                upd_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/applications",
                    data=_json.dumps(
                        {
                            "id": app_id,
                            "org": "OWASP Juice Shop",
                            "assessor": "Felipe Mestrado",
                            "target": "AL2",
                            "date": "2026-11-26",
                            "lastScanAt": "2026-11-26T14:30:00Z",
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(upd_req, timeout=5) as r2:
                    self.assertEqual(r2.status, 200)
                    d2 = _json.loads(r2.read().decode("utf-8"))
                self.assertEqual(d2["application"]["assessor"], "Felipe Mestrado")
                self.assertEqual(d2["application"]["target"], "AL2")
                self.assertEqual(d2["application"]["date"], "2026-11-26")

                # 5. Delete application -> 200
                del_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/applications?id={app_id}",
                    method="DELETE",
                )
                with urllib.request.urlopen(del_req, timeout=5) as r3:
                    self.assertEqual(r3.status, 200)
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/applications", timeout=5) as r4:
                    self.assertEqual(_json.loads(r4.read().decode("utf-8"))["applications"], [])
            finally:
                srv.shutdown()
                srv.server_close()
                srv_mod.APPS_STORE_PATH = orig_store

        # 6. Verify frontend enforces: pre-selection view, gated tabs, no editable date/assessor/target in Assessment
        html_txt = (ROOT_DIR / "casa-assessment" / "frontend" / "assess.html").read_text(encoding="utf-8")
        js_txt = (ROOT_DIR / "casa-assessment" / "frontend" / "app.js").read_text(encoding="utf-8")
        assess_section = html_txt.split('id="view-assess"', 1)[1].split('id="view-report"', 1)[0]
        self.assertIn('id="view-apps"', html_txt)
        self.assertIn('id="i18n-tab-apps"', html_txt)
        self.assertIn('id="i18n-tab-assess" data-view="assess" aria-pressed="false" disabled', html_txt)
        self.assertIn('id="i18n-tab-report" data-view="report" aria-pressed="false" disabled', html_txt)
        self.assertNotIn('type="date"', html_txt)
        self.assertNotIn('id="assessor"', assess_section)
        self.assertNotIn('id="target"', assess_section)
        self.assertIn('id="assessor-display" data-readonly="true"', assess_section)
        self.assertIn('id="target-display" data-readonly="true"', assess_section)
        self.assertIn('id="date-display" data-readonly="true"', assess_section)
        self.assertIn("/api/applications", js_txt)
        self.assertIn('switchView("apps")', js_txt)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("ITERAÇÃO SDD 194", just_neon)

    def test_iteration195_report_pass_evolution_and_history(self) -> None:
        """SDD 195: Scan history REST persistence, latest-by-default selector & Pass Rate evolution chart."""
        import http.server
        import json as _json
        import threading
        import urllib.request
        import casa_audit.server as srv_mod

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            orig_apps = srv_mod.APPS_STORE_PATH
            orig_hist = srv_mod.HISTORY_STORE_PATH
            srv_mod.APPS_STORE_PATH = tdp / "applications.json"
            srv_mod.HISTORY_STORE_PATH = tdp / "scan_history.json"
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), srv_mod.CasaAssessmentHandler)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                # 1. Register an application
                c_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/applications",
                    data=_json.dumps({"org": "Juice Shop", "assessor": "Felipe", "target": "AL1"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(c_req, timeout=5) as rc:
                    app_id = _json.loads(rc.read().decode("utf-8"))["application"]["id"]

                # 2. Save 3 scan runs out of chronological order and verify sorted retrieval
                sample_runs = [
                    {"id": "run-3", "executedAt": "2026-11-26T15:00:00Z", "date": "2026-11-26", "target": "AL1", "summary": {"passPct": 85, "passedCount": 50, "applicableCount": 59}, "answers": {"SCA-01": {"verdict": "PASS"}}},
                    {"id": "run-1", "executedAt": "2026-11-20T10:00:00Z", "date": "2026-11-20", "target": "AL1", "summary": {"passPct": 20, "passedCount": 12, "applicableCount": 59}, "answers": {"SCA-01": {"verdict": "FAIL"}}},
                    {"id": "run-2", "executedAt": "2026-11-23T12:30:00Z", "date": "2026-11-23", "target": "AL1", "summary": {"passPct": 55, "passedCount": 32, "applicableCount": 59}, "answers": {"SCA-01": {"verdict": "PASS"}}},
                ]
                for run_obj in sample_runs:
                    h_req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/applications/history",
                        data=_json.dumps({"app_id": app_id, "run": run_obj}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(h_req, timeout=5) as rh:
                        self.assertEqual(rh.status, 201)

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/applications/history?app_id={app_id}", timeout=5) as rg:
                    self.assertEqual(rg.status, 200)
                    hist_data = _json.loads(rg.read().decode("utf-8"))
                self.assertEqual(hist_data["count"], 3)
                self.assertEqual([r["id"] for r in hist_data["runs"]], ["run-1", "run-2", "run-3"])
                self.assertEqual([r["summary"]["passPct"] for r in hist_data["runs"]], [20, 55, 85])

                # 3. Deleting the application also purges its scan history
                d_req = urllib.request.Request(f"http://127.0.0.1:{port}/api/applications?id={app_id}", method="DELETE")
                with urllib.request.urlopen(d_req, timeout=5) as rd:
                    self.assertEqual(rd.status, 200)
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/applications/history?app_id={app_id}", timeout=5) as rg2:
                    self.assertEqual(_json.loads(rg2.read().decode("utf-8"))["runs"], [])
            finally:
                srv.shutdown()
                srv.server_close()
                srv_mod.APPS_STORE_PATH = orig_apps
                srv_mod.HISTORY_STORE_PATH = orig_hist

        # 4. Verify frontend evolution chart, latest-by-default selector, and cache-busting
        html_txt = (ROOT_DIR / "casa-assessment" / "frontend" / "assess.html").read_text(encoding="utf-8")
        js_txt = (ROOT_DIR / "casa-assessment" / "frontend" / "app.js").read_text(encoding="utf-8")
        css_txt = (ROOT_DIR / "casa-assessment" / "frontend" / "styles.css").read_text(encoding="utf-8")
        self.assertIn("app.js?v=sdd195", html_txt)
        self.assertIn("function passRateEvolutionChart(", js_txt)
        self.assertIn('id="report-run-select"', js_txt)
        self.assertIn("/api/applications/history", js_txt)
        self.assertIn("evo-point", js_txt)
        self.assertIn(".evolution-card", css_txt)
        self.assertIn(".report-history-bar", css_txt)

        just_neon = (ROOT_DIR / "docs" / "justificativaNeon.txt").read_text(encoding="utf-8")
        self.assertIn("ITERAÇÃO SDD 195", just_neon)


if __name__ == "__main__":
    unittest.main()

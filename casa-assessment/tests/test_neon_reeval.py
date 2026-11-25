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


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

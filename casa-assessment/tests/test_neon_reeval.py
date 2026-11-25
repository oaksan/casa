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


if __name__ == "__main__":
    unittest.main()

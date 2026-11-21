"""Automated tests for Iteration 1: CASA 3.0 Assessment Tool (SDD 001-casa3-assessment)."""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import unittest
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

from casa_audit.scanner import (
    CYCLONEDX_BIN,
    GITLEAKS_BIN,
    OSV_SCANNER_BIN,
    SYFT_BIN,
    TRIVY_BIN,
    build_reverse_dep_graph,
    compute_cvss3_base_score,
    compute_levenshtein_distance,
    compute_shannon_entropy,
    evaluate_oau05_system_browser_policy,
    evaluate_oau06_client_secret_scanner,
    evaluate_sast01_secrets_and_entropy,
    evaluate_sast02_trust_material_and_keys,
    evaluate_sca02_dependencies,
    evaluate_sca04_sbom_completeness,
    evaluate_sca05_malicious_and_typosquat,
    evaluate_whk01_delivery_tls,
    evaluate_whk02_hmac_and_timing_safe,
    evaluate_whk03_ssrf_and_signing_secrets,
    load_controls,
    parse_trivy_os_report,
    run_automated_al1_scan,
    run_cyclonedx_validate_and_diff,
    run_gitleaks_for_sast,
    run_gitleaks_git_history,
    trace_package_reachability,
)
from casa_audit.server import CasaAssessmentHandler

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_JSON = ROOT_DIR / "casa-assessment" / "data" / "casa3_controls.json"
FRONTEND_DIR = ROOT_DIR / "casa-assessment" / "frontend"


class TestCasa3Iteration1(unittest.TestCase):
    def test_dataset_has_61_al1_and_15_al2_controls(self) -> None:
        self.assertTrue(DATA_JSON.exists(), "casa3_controls.json must exist")
        payload = json.loads(DATA_JSON.read_text(encoding="utf-8"))
        self.assertEqual(sorted(payload["assurance_levels"].keys()), ["AL1", "AL2"])
        controls = payload["controls"]
        self.assertEqual(len(controls), 76)

        al1 = [c for c in controls if c["tier"] == "AL1"]
        al2 = [c for c in controls if c["tier"] == "AL2"]
        self.assertEqual(len(al1), 61)
        self.assertEqual(len(al2), 15)

        for c in controls:
            self.assertTrue(c.get("title_pt"), f"{c['id']} missing title_pt")
            self.assertTrue(c.get("domain_pt"), f"{c['id']} missing domain_pt")
            self.assertTrue(c.get("pass_criteria_pt"), f"{c['id']} missing pass_criteria_pt")
            self.assertTrue(c.get("fail_criteria_pt"), f"{c['id']} missing fail_criteria_pt")
            self.assertNotEqual(c["pass_criteria_pt"], c["pass_criteria"], f"{c['id']} pass_criteria_pt not translated")
            self.assertNotEqual(c["fail_criteria_pt"], c["fail_criteria"], f"{c['id']} fail_criteria_pt not translated")
            for forbidden_en in ["and whose", "whose vulnerable", "Every direct", "findings at"]:
                self.assertNotIn(forbidden_en, c["pass_criteria_pt"], f"{c['id']} contains untranslated '{forbidden_en}'")

        for c in al1:
            self.assertEqual(c["automation"], "automated")
            self.assertTrue(c["pass_criteria"], f"{c['id']} missing pass_criteria")
            self.assertTrue(c["fail_criteria"], f"{c['id']} missing fail_criteria")

        for c in al2:
            self.assertEqual(c["automation"], "lab_adjudicated")
            self.assertGreater(
                len(c["verification_checklist"]),
                0,
                f"AL2 control {c['id']} must have verification_checklist items",
            )

    def test_automated_al1_scanner_scoping_and_execution(self) -> None:
        results = run_automated_al1_scan(
            target_url="",
            repo_path=str(ROOT_DIR),
            surfaces=["Web_Application"],
        )
        self.assertEqual(len(results), 61)
        # OAU-05 and OAU-06 apply only to Mobile, Native -> must be NOT_APPLICABLE when only Web_Application is declared
        self.assertEqual(results["OAU-05"]["verdict"], "NOT_APPLICABLE")
        self.assertEqual(results["OAU-06"]["verdict"], "NOT_APPLICABLE")
        # SCA-01 and SAST-01 apply to All -> must be evaluated (PASS or FAIL)
        self.assertIn(results["SCA-01"]["verdict"], {"PASS", "FAIL"})
        self.assertIn(results["SAST-01"]["verdict"], {"PASS", "FAIL"})
        for cid, r in results.items():
            self.assertNotIn("... and ", r["log"], f"{cid} log is truncated")
            self.assertNotIn("... (+", r["log"], f"{cid} log is truncated")
            self.assertNotIn("non-blocking", r["log"].lower(), f"{cid} log leaks non-blocking findings")
            self.assertNotIn("informational", r["log"].lower(), f"{cid} log leaks informational findings")

        # Iteration 9-15: Verify CVSS v3.1 calculator, Levenshtein distance, Shannon entropy, SARIF generation, and docs/justificativa.txt
        self.assertEqual(compute_cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(compute_levenshtein_distance("ngy-cookie", "ngx-cookie"), 1)
        self.assertEqual(compute_levenshtein_distance("express", "express"), 0)
        self.assertGreater(compute_shannon_entropy("pa4qacea4VK9t9nGv7yZtwmj"), 3.8)
        self.assertTrue((ROOT_DIR / "casa-assessment" / "output" / "sca-findings.sarif").exists())
        just_txt = (ROOT_DIR / "docs" / "justificativa.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 01/61: SCA-01", just_txt)
        self.assertIn("CONTROLE 02/61: SCA-02", just_txt)
        self.assertIn("CONTROLE 03/61: SCA-03", just_txt)
        self.assertIn("CONTROLE 04/61: SCA-04", just_txt)
        self.assertIn("CONTROLE 05/61: SCA-05", just_txt)
        self.assertIn("CONTROLE 06/61: SAST-01", just_txt)
        self.assertIn("CONTROLE 07/61: SAST-02", just_txt)
        self.assertIn("CONTROLE 08/61: SAST-03", just_txt)
        self.assertIn("CONTROLE 09/61: SAST-04", just_txt)
        self.assertIn("CONTROLE 10/61: SAST-05", just_txt)
        self.assertIn("CONTROLE 11/61: SAST-06", just_txt)
        self.assertIn("CONTROLE 12/61: SAST-07", just_txt)
        self.assertIn("CONTROLE 13/61: SAST-08", just_txt)
        self.assertIn("CONTROLE 14/61: SAST-09", just_txt)
        self.assertIn("CONTROLE 15/61: SAST-10", just_txt)
        self.assertIn("CONTROLE 16/61: SAST-11", just_txt)
        self.assertIn("CONTROLE 17/61: SAST-12", just_txt)
        self.assertIn("CONTROLE 18/61: SAST-13", just_txt)
        self.assertIn("CONTROLE 19/61: TLS-01", just_txt)
        self.assertIn("CONTROLE 20/61: TLS-02", just_txt)
        self.assertIn("CONTROLE 21/61: TLS-03", just_txt)
        self.assertIn("CONTROLE 22/61: TLS-04", just_txt)
        self.assertIn("CONTROLE 23/61: TLS-05", just_txt)
        self.assertIn("CONTROLE 24/61: TLS-06", just_txt)
        self.assertIn("CONTROLE 25/61: CFG-01", just_txt)
        self.assertIn("CONTROLE 26/61: CFG-02", just_txt)
        self.assertIn("CONTROLE 27/61: CFG-03", just_txt)
        self.assertIn("CONTROLE 28/61: CFG-04", just_txt)
        self.assertIn("CONTROLE 29/61: CFG-05", just_txt)
        self.assertIn("CONTROLE 30/61: CFG-06", just_txt)
        self.assertIn("CONTROLE 31/61: CFG-07", just_txt)
        self.assertIn("CONTROLE 32/61: CFG-08", just_txt)
        self.assertIn("CONTROLE 33/61: CFG-09", just_txt)
        self.assertIn("CONTROLE 34/61: CFG-10", just_txt)
        self.assertIn("CONTROLE 35/61: CFG-11", just_txt)
        self.assertIn("CONTROLE 36/61: AUT-01", just_txt)
        self.assertIn("CONTROLE 37/61: AUT-02", just_txt)
        self.assertIn("CONTROLE 38/61: AUT-03", just_txt)
        self.assertIn("CONTROLE 39/61: AUT-04", just_txt)
        self.assertIn("CONTROLE 40/61: AUT-05", just_txt)
        self.assertIn("CONTROLE 41/61: AUT-06", just_txt)
        self.assertIn("CONTROLE 42/61: AUT-07", just_txt)
        self.assertIn("CONTROLE 43/61: AUT-08", just_txt)
        self.assertIn("CONTROLE 44/61: AZI-01", just_txt)
        self.assertIn("CONTROLE 45/61: AZI-02", just_txt)
        self.assertIn("CONTROLE 46/61: AZI-03", just_txt)
        self.assertIn("CONTROLE 47/61: AZI-04", just_txt)
        self.assertIn("CONTROLE 48/61: AZI-05", just_txt)
        self.assertIn("CONTROLE 49/61: AZI-06", just_txt)
        self.assertIn("CONTROLE 50/61: OAU-01", just_txt)
        self.assertIn("CONTROLE 51/61: OAU-02", just_txt)
        self.assertIn("CONTROLE 52/61: OAU-03", just_txt)
        self.assertIn("CONTROLE 53/61: OAU-04", just_txt)
        self.assertIn("CONTROLE 54/61: OAU-05", just_txt)

        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            (td / "LoginActivity.kt").write_text(
                'val wv = WebView(ctx)\nwv.loadUrl("https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&response_type=code")',
                encoding="utf-8",
            )
            (td / "AuthVC.swift").write_text("let vc = SFSafariViewController(url: authUrl)", encoding="utf-8")
            v_fail, _, _, hits_fail, _ = evaluate_oau05_system_browser_policy(td)
            self.assertEqual(v_fail, "FAIL")
            self.assertEqual(len(hits_fail), 2)

            (td / "LoginActivity.kt").write_text("CustomTabsIntent.Builder().build().launchUrl(ctx, authUri)", encoding="utf-8")
            (td / "AuthVC.swift").write_text('ASWebAuthenticationSession(url: authUrl, callbackURLScheme: "myapp")', encoding="utf-8")
            v_pass, _, _, hits_pass, app_hits = evaluate_oau05_system_browser_policy(td)
            self.assertEqual(v_pass, "PASS")
            self.assertEqual(hits_pass, [])
            self.assertIn("CustomTabsIntent", app_hits)
            self.assertIn("ASWebAuthenticationSession", app_hits)

        self.assertIn("CONTROLE 55/61: OAU-06", just_txt)
        self.assertIn("CONTROLE 56/61: OAU-07", just_txt)
        self.assertIn("CONTROLE 57/61: OAU-08", just_txt)
        self.assertIn("CONTROLE 58/61: OAU-09", just_txt)
        self.assertIn("CONTROLE 59/61: WHK-01", just_txt)

        wf_fail, _, wf_hits, _ = evaluate_whk01_delivery_tls(
            ["https://hooks.example.com/webhook"],
            webhook_files={"hooks.ts": "const webhookUrl = 'http://hooks.example.com/webhook'"},
            http_fn=lambda *a, **kw: (202, {}, "accepted"),
            tls_matrix_fn=lambda h, p: {"TLS 1.0": "offered", "TLS 1.1": "not offered", "TLS 1.2": "offered", "TLS 1.3": "not offered"},
        )
        self.assertEqual(wf_fail, "FAIL")
        self.assertGreaterEqual(len(wf_hits), 3)

        wf_pass, _, wf_hits_p, _ = evaluate_whk01_delivery_tls(
            ["https://hooks.example.com/webhook"],
            http_fn=lambda *a, **kw: (301, {"location": "https://hooks.example.com/webhook"}, ""),
            tls_matrix_fn=lambda h, p: {"TLS 1.0": "not offered", "TLS 1.1": "not offered", "TLS 1.2": "offered", "TLS 1.3": "offered"},
        )
        self.assertEqual(wf_pass, "PASS")
        self.assertEqual(wf_hits_p, [])

        self.assertIn("CONTROLE 60/61: WHK-02", just_txt)
        w2_fail, _, w2_hits, w2_cls_f = evaluate_whk02_hmac_and_timing_safe(
            ["https://hooks.example.com/webhook"],
            webhook_files={"whk.ts": "const expected = crypto.createHmac('sha1', sec).update(body).digest('hex'); if (sig === expected) return true"},
            http_fn=lambda *a, **kw: (200, {}, "ok"),
        )
        self.assertEqual(w2_fail, "FAIL")
        self.assertEqual(len(w2_hits), 6)
        self.assertEqual(w2_cls_f["timing_safe_compare"], "FAIL")

        w2_pass, _, w2_hits_p, w2_cls_p = evaluate_whk02_hmac_and_timing_safe(
            ["https://hooks.example.com/webhook"],
            webhook_files={"whk.ts": "const exp = crypto.createHmac('sha256', sec).update(body).digest(); crypto.timingSafeEqual(sigBuf, exp)"},
            http_fn=lambda *a, **kw: (401, {}, "unauthorized"),
        )
        self.assertEqual(w2_pass, "PASS")
        self.assertEqual(w2_hits_p, [])
        self.assertEqual(w2_cls_p, {"mac_algorithm": "PASS", "timing_safe_compare": "PASS"})

        self.assertIn("CONTROLE 61/61: WHK-03", just_txt)
        self.assertIn("ITERAÇÃO SDD 070", just_txt)
        w3_fail, w3_pr_f, w3_hits_f, _ = evaluate_whk03_ssrf_and_signing_secrets(
            ["https://hooks.example.com/api/webhooks/register"],
            webhook_files={"hooks.ts": "const wh = 'whsec_RealTestSecretValue1234567890'"},
            http_fn=lambda *a, **kw: (201, {}, "registered"),
        )
        self.assertEqual(w3_fail, "FAIL")
        self.assertEqual(w3_pr_f, 11)
        self.assertGreaterEqual(len(w3_hits_f), 11)

        w3_pass, w3_pr_p, w3_hits_p, w3_oob_p = evaluate_whk03_ssrf_and_signing_secrets(
            ["https://hooks.example.com/api/webhooks/register"],
            webhook_files={"hooks.ts": "const s = process.env.WEBHOOK_SECRET"},
            http_fn=lambda *a, **kw: (400, {}, "blocked private url"),
        )
        self.assertEqual(w3_pass, "PASS")
        self.assertEqual(w3_pr_p, 11)
        self.assertEqual(w3_oob_p, 0)
        self.assertEqual(w3_hits_p, [])
        with tempfile.TemporaryDirectory() as tmpdir6:
            td6 = Path(tmpdir6)
            (td6 / "app.apk").write_bytes(
                b'PK\x03\x04client_id="mob-client-01" client_secret="GOCSPX-RealLeakedSecret9876543210"'
            )
            v6_fail, _, bins6, hits6, cids6 = evaluate_oau06_client_secret_scanner(td6)
            self.assertEqual(v6_fail, "FAIL")
            self.assertEqual(bins6, 1)
            self.assertIn("mob-client-01", cids6)
            self.assertGreaterEqual(len(hits6), 2)

            (td6 / "app.apk").unlink()
            (td6 / "AuthConfig.kt").write_text('val clientId = "mob-public-pkce-01"', encoding="utf-8")
            v6_pass, _, _, hits6_p, cids6_p = evaluate_oau06_client_secret_scanner(td6)
            self.assertEqual(v6_pass, "PASS")
            self.assertEqual(hits6_p, [])
            self.assertIn("mob-public-pkce-01", cids6_p)

    def test_http_server_and_api_scan_endpoint(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), CasaAssessmentHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # 1. Verify assess.html is served
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/assess.html", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                html = resp.read().decode("utf-8")
                self.assertIn("CASA 3.0 Assessment", html)
                self.assertIn('data-lang="pt"', html)
                self.assertIn('data-lang="en"', html)
                self.assertIn('id="btn-run-auto"', html)
                self.assertNotIn('id="btn-demo-auto"', html)
                self.assertNotIn('id="evidence-upload"', html)
                self.assertIn("data.js", html)
                self.assertIn("app.js", html)

            app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
            self.assertIn('triageNotesLbl: "Notas do Avaliador"', app_js)
            self.assertIn('triageNotesPh: "Notas como controles compensatórios"', app_js)

            # 2. Verify POST /api/scan returns 61 AL1 automated verdicts
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=json.dumps(
                    {
                        "target_url": "",
                        "repo_path": str(ROOT_DIR),
                        "surfaces": ["Web_Application"],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(body["status"], "ok")
                self.assertEqual(body["count"], 61)
        finally:
            server.shutdown()
            server.server_close()

    def test_iteration71_sca01_guide_tooling(self) -> None:
        self.assertTrue(Path(SYFT_BIN).exists(), f"syft binary not found at {SYFT_BIN}")
        self.assertTrue(Path(OSV_SCANNER_BIN).exists(), f"osv-scanner binary not found at {OSV_SCANNER_BIN}")
        self.assertTrue((ROOT_DIR / "casa-assessment" / "output" / "sbom.cdx.json").exists())
        self.assertTrue((ROOT_DIR / "casa-assessment" / "output" / "sca-findings.sarif").exists())
        self.assertTrue((ROOT_DIR / "casa-assessment" / "output" / "osv-scanner.sarif").exists())

        with tempfile.TemporaryDirectory() as td_sca:
            r_sca = Path(td_sca)
            (r_sca / "lib").mkdir()
            (r_sca / "lib" / "auth.ts").write_text(
                "import expressJwt from 'express-jwt';\nexport const mw = expressJwt({ secret: 'x' });\n",
                encoding="utf-8",
            )
            fake_sbom = {
                "components": [
                    {"bom-ref": "pkg:npm/express-jwt@0.1.3", "name": "express-jwt", "version": "0.1.3"},
                    {"bom-ref": "pkg:npm/jsonwebtoken@0.1.0", "name": "jsonwebtoken", "version": "0.1.0"},
                    {"bom-ref": "pkg:npm/jws@0.2.6", "name": "jws", "version": "0.2.6"},
                    {"bom-ref": "pkg:npm/@cyclonedx/cyclonedx-npm@4.2.1", "name": "@cyclonedx/cyclonedx-npm", "version": "4.2.1"},
                ],
                "dependencies": [
                    {"ref": "pkg:npm/express-jwt@0.1.3", "dependsOn": ["pkg:npm/jsonwebtoken@0.1.0"]},
                    {"ref": "pkg:npm/jsonwebtoken@0.1.0", "dependsOn": ["pkg:npm/jws@0.2.6"]},
                ],
            }
            rev_graph = build_reverse_dep_graph(r_sca, fake_sbom)
            cache: dict[str, tuple[bool, list[str]]] = {}
            reach_jws, traces_jws = trace_package_reachability(r_sca, "jws", rev_graph, cache)
            reach_cli, _ = trace_package_reachability(r_sca, "@cyclonedx/cyclonedx-npm", rev_graph, cache)
            self.assertTrue(reach_jws, "Transitive dependency jws via express-jwt must be reachable")
            self.assertTrue(any("express-jwt" in t for t in traces_jws))
            self.assertFalse(reach_cli, "Unimported dev CLI tool must remain unreachable")

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 01/61: SCA-01 (Iteração SDD 071)", just2_txt)

    def test_iteration72_sca02_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sca2:
            r2 = Path(td_sca2)
            # 1. Untrusted non-canonical registry in package-lock.json + EOL Node engine + untrusted PyPI source
            (r2 / "package.json").write_text(
                json.dumps({
                    "name": "sca02-test",
                    "engines": {"node": "16.x"},
                    "dependencies": {"evilpkg": "^1.0.0"},
                }),
                encoding="utf-8",
            )
            (r2 / "package-lock.json").write_text(
                json.dumps({
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"evilpkg": "^1.0.0"}},
                        "node_modules/evilpkg": {
                            "version": "1.0.1",
                            "resolved": "http://untrusted.example.com/evilpkg-1.0.1.tgz",
                        },
                    },
                }),
                encoding="utf-8",
            )
            (r2 / "requirements.txt").write_text(
                "internal-pkg @ git+https://evil.example.com/repo.git\n",
                encoding="utf-8",
            )
            fails, sarifs, stats = evaluate_sca02_dependencies(
                r2,
                [("npm", "evilpkg", "1.0.0"), ("PyPI", "internal-pkg", "0.1.0")],
            )
            joined = "\n".join(fails)
            self.assertIn("evilpkg@1.0.1", joined)
            self.assertIn("Untrusted/unpinned source registry", joined)
            self.assertIn("nodejs@16", joined)
            self.assertIn("Untrusted direct PyPI source URL", joined)
            self.assertGreaterEqual(stats["untrusted_registry"], 2)
            self.assertGreaterEqual(stats["eol_or_deprecated"], 1)
            self.assertTrue(any(s.get("ruleId") == "CASA3-SCA-02" for s in sarifs))

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 02/61: SCA-02 (Iteração SDD 072)", just2_txt)

    def test_iteration73_sca03_guide_tooling(self) -> None:
        self.assertTrue(Path(TRIVY_BIN).exists(), f"trivy binary not found at {TRIVY_BIN}")
        sample_trivy = {
            "Metadata": {"OS": {"Family": "debian", "Name": "13.7"}},
            "Results": [
                {
                    "Class": "os-pkgs",
                    "Packages": [
                        {
                            "Name": "libssl3t64",
                            "Version": "3.5.7-1~deb13u3",
                            "SrcName": "openssl",
                            "Identifier": {"PURL": "pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3"},
                        },
                        {
                            "Name": "tar",
                            "Version": "1.35+dfsg-3",
                            "SrcName": "tar",
                            "Identifier": {"PURL": "pkg:deb/debian/tar@1.35+dfsg-3"},
                        },
                    ],
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-124709",
                            "PkgName": "libssl3t64",
                            "InstalledVersion": "3.5.7-1~deb13u3",
                            "Severity": "HIGH",
                            "Status": "affected",
                            "CVSS": {"nvd": {"V3Score": 7.5}},
                        },
                        {
                            "VulnerabilityID": "CVE-2024-999999",
                            "PkgName": "tar",
                            "InstalledVersion": "1.35+dfsg-3",
                            "Severity": "HIGH",
                            "Status": "will_not_fix",
                            "CVSS": {"nvd": {"V3Score": 7.8}},
                        },
                    ],
                }
            ],
        }
        os_comps, blocking, excluded, sarifs, distro = parse_trivy_os_report(sample_trivy)
        self.assertEqual(distro, "Debian:13.7")
        self.assertEqual(len(os_comps), 2)
        self.assertEqual(len(blocking), 1)
        self.assertIn("CVE-2026-124709", blocking[0])
        self.assertIn("fix=unfixed", blocking[0])
        self.assertEqual(len(excluded), 1)
        self.assertIn("will_not_fix", excluded[0])
        self.assertEqual(len(sarifs), 1)
        self.assertEqual(sarifs[0]["ruleId"], "CASA3-SCA-03")

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 03/61: SCA-03 (Iteração SDD 073)", just2_txt)

    def test_iteration74_sca04_guide_tooling(self) -> None:
        self.assertTrue(Path(CYCLONEDX_BIN).exists(), f"cyclonedx-cli binary not found at {CYCLONEDX_BIN}")
        with tempfile.TemporaryDirectory() as td_sca4:
            r4 = Path(td_sca4)
            assessor_comps = [
                {
                    "type": "library",
                    "bom-ref": "pkg:npm/express@4.22.1",
                    "supplier": {"name": "npm registry"},
                    "name": "express",
                    "version": "4.22.1",
                    "purl": "pkg:npm/express@4.22.1",
                }
            ]
            assessor_sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
                "version": 1,
                "metadata": {
                    "timestamp": "2026-11-21T00:00:00Z",
                    "tools": [{"vendor": "Anchore", "name": "syft", "version": "1.57.2"}],
                    "component": {"type": "application", "name": "app", "bom-ref": "app"},
                },
                "components": assessor_comps,
                "dependencies": [{"ref": "app", "dependsOn": ["pkg:npm/express@4.22.1"]}],
            }
            a_path = r4 / "assessor.cdx.json"
            a_path.write_text(json.dumps(assessor_sbom), encoding="utf-8")
            p_path = r4 / "bom.json"
            p_path.write_text(json.dumps(assessor_sbom), encoding="utf-8")
            diff_path = r4 / "diff.json"

            # 1. Complete matching published BOM passes both cyclonedx validate and set-difference
            v_ok, msg_ok, diff_ran, diff_data = run_cyclonedx_validate_and_diff(p_path, "1.5", a_path, diff_path)
            self.assertTrue(v_ok, f"Expected valid CycloneDX 1.5 BOM: {msg_ok}")
            self.assertTrue(diff_ran and diff_data is not None)
            verdict_p, fails_p, _, _ = evaluate_sca04_sbom_completeness(r4, assessor_comps, a_path)
            self.assertEqual(verdict_p, "PASS", f"Expected PASS, got fails={fails_p}")

            # 2. Published BOM missing component fails Set Difference
            bad_pub = dict(assessor_sbom, components=[])
            p_path.write_text(json.dumps(bad_pub), encoding="utf-8")
            verdict_f, fails_f, sarif_f, _ = evaluate_sca04_sbom_completeness(r4, assessor_comps, a_path)
            self.assertEqual(verdict_f, "FAIL")
            self.assertTrue(any("ABSENT from published SBOM" in f for f in fails_f))
            self.assertTrue(any(s.get("ruleId") == "CASA3-SCA-04" for s in sarif_f))

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 04/61: SCA-04 (Iteração SDD 074)", just2_txt)

    def test_iteration75_sca05_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sca5:
            r5 = Path(td_sca5)
            # 1. Repository with compromised package scanned via osv-scanner
            (r5 / "package.json").write_text(
                json.dumps({"name": "sca05-fail", "dependencies": {"eslint-scope": "3.7.2"}}),
                encoding="utf-8",
            )
            v_fail, fails5, sarif5, meta5 = evaluate_sca05_malicious_and_typosquat(r5)
            self.assertEqual(v_fail, "FAIL")
            self.assertIn("osv-scanner", meta5)
            self.assertTrue(any("eslint-scope@3.7.2" in f for f in fails5))
            self.assertTrue(any(s.get("ruleId") == "CASA3-SCA-05" for s in sarif5))

            # 2. Synthetic MAL-* advisory passed via lockfile osv_data
            synthetic_osv = {
                "results": [
                    {
                        "source": {"path": str(r5 / "package-lock.json")},
                        "packages": [
                            {
                                "package": {"name": "evil-typosquat", "version": "1.0.0", "ecosystem": "npm"},
                                "vulnerabilities": [{"id": "MAL-2026-0001", "summary": "Malicious package"}],
                            }
                        ],
                    }
                ]
            }
            (r5 / "package.json").write_text(
                json.dumps({"name": "sca05-clean-manifest", "dependencies": {"express": "4.22.1"}}),
                encoding="utf-8",
            )
            v_mal, fails_mal, _, _ = evaluate_sca05_malicious_and_typosquat(r5, osv_data=synthetic_osv)
            self.assertEqual(v_mal, "FAIL")
            self.assertTrue(any("MAL-2026-0001" in f for f in fails_mal))

            # 3. Clean canonical dependency passes
            v_pass, fails_p, _, _ = evaluate_sca05_malicious_and_typosquat(r5)
            self.assertEqual(v_pass, "PASS", f"Expected PASS, got {fails_p}")

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 05/61: SCA-05 (Iteração SDD 075)", just2_txt)

    def test_iteration76_sast01_guide_tooling(self) -> None:
        self.assertTrue(Path(GITLEAKS_BIN).exists(), f"gitleaks binary not found at {GITLEAKS_BIN}")
        with tempfile.TemporaryDirectory() as td_sast1:
            r1 = Path(td_sast1)
            (r1 / "src").mkdir()
            # GitHub PAT style high-entropy token in source + triaged mock in .spec.ts
            fake_tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
            (r1 / "src" / "config.ts").write_text(
                f"export const GH_TOKEN = '{fake_tok}';\n",
                encoding="utf-8",
            )
            (r1 / "src" / "config.spec.ts").write_text(
                f"const mockTok = '{fake_tok}';\n",
                encoding="utf-8",
            )
            hits, gl_ran = run_gitleaks_for_sast(r1)
            self.assertTrue(gl_ran)
            self.assertTrue(any("src/config.ts" in str(h.get("File")) for h in hits))
            self.assertFalse(any("config.spec.ts" in str(h.get("File")) for h in hits))

            findings, sarifs = evaluate_sast01_secrets_and_entropy(r1, gitleaks_hits=hits)
            self.assertTrue(any("[GITLEAKS" in f and "src/config.ts" in f for f in findings))
            self.assertTrue(any(s.get("ruleId", "").startswith("CASA3-SAST-01-gitleaks-") for s in sarifs))

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 06/61: SAST-01 (Iteração SDD 076)", just2_txt)

    def test_iteration77_sast02_guide_tooling(self) -> None:
        self.assertTrue(Path(GITLEAKS_BIN).exists(), f"gitleaks binary not found at {GITLEAKS_BIN}")
        with tempfile.TemporaryDirectory() as td_sast2:
            r2 = Path(td_sast2)
            # 1. Clean repository yields zero SAST-02 findings
            (r2 / "src").mkdir()
            (r2 / "src" / "app.ts").write_text("export const ok = true;\n", encoding="utf-8")
            f_clean, _ = evaluate_sast02_trust_material_and_keys(r2, gitleaks_dir_hits=[], gitleaks_git_hits=[])
            self.assertEqual(f_clean, [])

            # 2. Shipped archive (.zip) containing trust-material certificate/key triggers SAST-02
            (r2 / "artifacts").mkdir()
            with zipfile.ZipFile(r2 / "artifacts" / "release.zip", "w") as zf:
                zf.writestr("certs/server.crt", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            f_arch, s_arch = evaluate_sast02_trust_material_and_keys(r2, gitleaks_dir_hits=[], gitleaks_git_hits=[])
            self.assertTrue(any("artifacts/release.zip!certs/server.crt" in f for f in f_arch))
            self.assertTrue(any(s.get("ruleId") == "CASA3-SAST-02-artifact-trust-material" for s in s_arch))

            # 3. Ephemeral Git repo where an RSA private key is committed and removed from HEAD
            git_repo = Path(td_sast2) / "git_hist"
            git_repo.mkdir()
            subprocess.run(["git", "-C", str(git_repo), "init"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(git_repo), "config", "user.email", "ci@example.com"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(git_repo), "config", "user.name", "CI"], check=True, capture_output=True)
            subprocess.run(
                ["openssl", "genrsa", "-out", str(git_repo / "legacy.pem"), "1024"],
                check=True,
                capture_output=True,
            )
            subprocess.run(["git", "-C", str(git_repo), "add", "legacy.pem"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(git_repo), "commit", "-m", "init key"], check=True, capture_output=True)
            (git_repo / "legacy.pem").unlink()
            subprocess.run(["git", "-C", str(git_repo), "add", "-u"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(git_repo), "commit", "-m", "remove key"], check=True, capture_output=True)

            git_hits, git_ran = run_gitleaks_git_history(git_repo)
            self.assertTrue(git_ran)
            self.assertTrue(any("private-key" in str(h.get("RuleID", "")).lower() for h in git_hits))
            f_git, s_git = evaluate_sast02_trust_material_and_keys(git_repo, gitleaks_dir_hits=[], gitleaks_git_hits=git_hits)
            self.assertTrue(any("[GITLEAKS GIT HISTORY" in f for f in f_git))
            self.assertTrue(any("CASA3-SAST-02-gitleaks-git-" in s.get("ruleId", "") for s in s_git))

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 07/61: SAST-02 (Iteração SDD 077)", just2_txt)


if __name__ == "__main__":
    unittest.main()

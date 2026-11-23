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
    evaluate_sast03_banned_ciphers,
    evaluate_sast04_weak_hashes,
    evaluate_sast05_password_kdf,
    evaluate_sast06_csprng_randomness,
    evaluate_sast07_framework_binding,
    evaluate_sast07_mass_assignment_probe,
    evaluate_sast08_sql_injection,
    evaluate_sast09_deserialization,
    evaluate_sast10_dynamic_execution,
    evaluate_sast11_path_traversal,
    evaluate_sast12_secrets_management_and_iac,
    evaluate_sast13_canary_log_replay,
    evaluate_sast13_sensitive_logging,
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
            with urllib.request.urlopen(req, timeout=60) as resp:
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

    def test_iteration78_sast03_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sast3:
            r3 = Path(td_sast3)
            src = r3 / "src"
            src.mkdir()
            # 1. Compliant AES-256-GCM across TS and Python yields PASS
            (src / "good.ts").write_text(
                "import crypto from 'crypto';\nexport const enc = (k: Buffer, iv: Buffer) => crypto.createCipheriv('aes-256-gcm', k, iv);\n",
                encoding="utf-8",
            )
            (src / "good.py").write_text(
                "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\ncipher = AESGCM(b'0'*32)\n",
                encoding="utf-8",
            )
            v_pass, f_pass, _, _ = evaluate_sast03_banned_ciphers(r3)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for AES-GCM, got {f_pass}")
            self.assertEqual(f_pass, [])

            # 2. Multi-language banned cipher detection (JS/TS, Python, Java, Go, C#)
            (src / "bad.ts").write_text(
                "import crypto from 'crypto';\nconst c = crypto.createCipheriv('rc4', k, iv);\nconst p = CryptoJS.TripleDES.decrypt(ct, key);\n",
                encoding="utf-8",
            )
            (src / "bad.py").write_text(
                "from Crypto.Cipher import AES\nc1 = AES.new(k, AES.MODE_ECB)\nc2 = cryptography.hazmat.decrepit.ciphers.algorithms.Blowfish(k)\n",
                encoding="utf-8",
            )
            (src / "Bad.java").write_text(
                'import javax.crypto.Cipher;\nclass Bad { void f() throws Exception { Cipher.getInstance("DES/ECB/PKCS5Padding"); } }\n',
                encoding="utf-8",
            )
            (src / "bad.go").write_text(
                'package p\nimport "crypto/rc4"\nfunc f(k []byte) { rc4.NewCipher(k) }\n',
                encoding="utf-8",
            )
            (src / "Bad.cs").write_text(
                "using System.Security.Cryptography;\nclass Bad { void F() { var d = TripleDES.Create(); } }\n",
                encoding="utf-8",
            )
            v_fail, f_fail, sarif_fail, _ = evaluate_sast03_banned_ciphers(r3)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("bad.ts", "bad.py", "Bad.java", "bad.go", "Bad.cs"):
                self.assertIn(fname, joined, f"Missing SAST-03 hit for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(sarif_fail), 6)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 08/61: SAST-03 (Iteração SDD 078)", just2_txt)

    def test_iteration79_sast04_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sast4:
            r4 = Path(td_sast4)
            src = r4 / "src"
            src.mkdir()
            # 1. Non-security ETag / cache-key MD5 uses yield PASS with informational notices (no error taint paths)
            (src / "etag.ts").write_text(
                "import crypto from 'crypto';\nexport const send = (body: string, res: any) => {\n  const etag = crypto.createHash('md5').update(body).digest('hex');\n  res.setHeader('ETag', etag);\n};\n",
                encoding="utf-8",
            )
            (src / "cache.py").write_text(
                "import hashlib\ndef key_for(u: str) -> str:\n    cache_key = hashlib.md5(u.encode()).hexdigest()\n    return cache_key\n",
                encoding="utf-8",
            )
            v_pass, f_pass, err_s_pass, info_s_pass, _ = evaluate_sast04_weak_hashes(r4)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for ETag/cache-key MD5, got {f_pass}")
            self.assertEqual(err_s_pass, [])
            self.assertGreaterEqual(len(info_s_pass), 2)

            # 2. Data-flow taint from MD5/SHA-1 into security sinks yields FAIL at error level
            (src / "auth.ts").write_text(
                "import crypto from 'crypto';\nexport const mk = (p: string) => {\n  const d = crypto.createHash('sha1').update(p).digest('hex');\n  return { password: d };\n};\n",
                encoding="utf-8",
            )
            (src / "auth.py").write_text(
                "import hashlib\ndef store(p: bytes):\n    h = hashlib.md5(p).hexdigest()\n    password_hash = h\n    return password_hash\n",
                encoding="utf-8",
            )
            (src / "Auth.java").write_text(
                'import java.security.MessageDigest;\nclass Auth { String mk(byte[] p) throws Exception { var md = MessageDigest.getInstance("SHA-1"); byte[] token = md.digest(p); return new String(token); } }\n',
                encoding="utf-8",
            )
            (src / "auth.go").write_text(
                'package p\nimport ("crypto/md5"; "crypto/subtle")\nfunc mk(k, exp []byte) int { h := md5.New(); token := h.Sum(k); return subtle.ConstantTimeCompare(token, exp) }\n',
                encoding="utf-8",
            )
            v_fail, f_fail, err_s_fail, _, _ = evaluate_sast04_weak_hashes(r4)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("auth.ts", "auth.py", "Auth.java", "auth.go"):
                self.assertIn(fname, joined, f"Missing SAST-04 taint hit for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(err_s_fail), 4)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 09/61: SAST-04 (Iteração SDD 079)", just2_txt)

    def test_iteration80_sast05_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sast5:
            r5 = Path(td_sast5)
            src = r5 / "src"
            src.mkdir()
            # 1. Compliant Argon2id + PBKDF2-HMAC-SHA256 with randomBytes CSPRNG salt + bcrypt cost=12 -> 0 findings
            (src / "kdf_ok.ts").write_text(
                "import crypto from 'crypto';\n"
                "import bcrypt from 'bcrypt';\n"
                "import argon2 from 'argon2';\n"
                "export async function hashA(pw: string) {\n"
                "  return argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });\n"
                "}\n"
                "export function hashP(pw: string) {\n"
                "  const salt = crypto.randomBytes(16);\n"
                "  return crypto.pbkdf2Sync(pw, salt, 600000, 32, 'sha256');\n"
                "}\n"
                "export function hashB(pw: string) { return bcrypt.hashSync(pw, 12); }\n",
                encoding="utf-8",
            )
            f_ok, _ = evaluate_sast05_password_kdf(r5)
            self.assertEqual(f_ok, [], f"Expected 0 SAST-05 findings for NIST-compliant KDFs, got {f_ok}")

            # 2. Sub-floor cost, non-CSPRNG/unproven salt, wrong Argon2 variant, dynamic unprovable cost -> FAIL
            (src / "kdf_bad.ts").write_text(
                "import crypto from 'crypto';\n"
                "import bcrypt from 'bcrypt';\n"
                "import argon2 from 'argon2';\n"
                "export function badBcrypt(pw: string, r: number) { return bcrypt.hashSync(pw, r); }\n"
                "export function badSalt(pw: string) { const s = Math.random().toString(); return crypto.pbkdf2Sync(pw, s, 600000, 32, 'sha256'); }\n"
                "export function badDigest(pw: string) { const s = crypto.randomBytes(16); return crypto.pbkdf2Sync(pw, s, 600000, 32, 'sha1'); }\n"
                "export function badScrypt(pw: string) { const s = crypto.randomBytes(16); return crypto.scryptSync(pw, s, 64, { N: 16384 }); }\n"
                "export async function badArgon(pw: string) { return argon2.hash(pw, { type: argon2.argon2i, memoryCost: 19456, timeCost: 2 }); }\n",
                encoding="utf-8",
            )
            (src / "kdf_bad.py").write_text(
                "import hashlib, bcrypt, secrets\n"
                "def b1(): return bcrypt.gensalt(rounds=8)\n"
                "def b2(pw): s = secrets.token_bytes(16); return hashlib.pbkdf2_hmac('sha256', pw, s, 250000)\n",
                encoding="utf-8",
            )
            f_bad, s_bad = evaluate_sast05_password_kdf(r5)
            joined = "\n".join(f_bad)
            self.assertIn("UNPROVABLE KDF COST", joined)
            self.assertIn("NON-CSPRNG PBKDF2 SALT", joined)
            self.assertIn("kdf_bad.ts:6", joined)
            self.assertIn("kdf_bad.ts:7", joined)
            self.assertIn("CASA3-SAST-05-weak-password-kdf", joined)
            self.assertIn("UNAPPROVED ARGON2 VARIANT", joined)
            self.assertIn("kdf_bad.py:2", joined)
            self.assertIn("kdf_bad.py:3", joined)
            self.assertGreaterEqual(len(s_bad), 7)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 10/61: SAST-05 (Iteração SDD 080)", just2_txt)

    def test_iteration81_sast06_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sast6:
            r6 = Path(td_sast6)
            src = r6 / "src"
            src.mkdir()
            # 1. CSPRNG randomness + benign non-security random (price/quantity) -> PASS
            (src / "csprng_ok.ts").write_text(
                "import crypto from 'crypto';\n"
                "export const mkToken = () => { const token = crypto.randomBytes(32).toString('hex'); return token; };\n"
                "export const mockPrice = () => { const price = Math.floor(Math.random() * 100); return price; };\n",
                encoding="utf-8",
            )
            (src / "csprng_ok.py").write_text(
                "import secrets\ndef mk_reset():\n    reset_token = secrets.token_urlsafe(32)\n    return reset_token\n",
                encoding="utf-8",
            )
            v_pass, f_pass, _, _ = evaluate_sast06_csprng_randomness(r6)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for CSPRNG & benign Math.random, got {f_pass}")
            self.assertEqual(f_pass, [])

            # 2. Multi-language non-CSPRNG & time-based taint into security sinks -> FAIL
            (src / "rng_bad.ts").write_text(
                "export function mkReset() {\n  const r = Math.random().toString(36);\n  const resetToken = r;\n  return resetToken;\n}\n",
                encoding="utf-8",
            )
            (src / "rng_bad.py").write_text(
                "import time\ndef mk_nonce():\n    s = str(time.time())\n    nonce = s\n    return nonce\n",
                encoding="utf-8",
            )
            (src / "RngBad.java").write_text(
                "import javax.crypto.spec.IvParameterSpec;\nclass RngBad { IvParameterSpec mk() { long t = System.currentTimeMillis(); byte[] iv = new byte[]{(byte)t}; return new IvParameterSpec(iv); } }\n",
                encoding="utf-8",
            )
            (src / "rng_bad.go").write_text(
                'package p\nimport "math/rand"\nfunc mk() int { v := rand.Intn(999999); token := v; return token }\n',
                encoding="utf-8",
            )
            v_fail, f_fail, sarif_fail, _ = evaluate_sast06_csprng_randomness(r6)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("rng_bad.ts", "rng_bad.py", "RngBad.java", "rng_bad.go"):
                self.assertIn(fname, joined, f"Missing SAST-06 taint hit for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(sarif_fail), 4)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 11/61: SAST-06 (Iteração SDD 081)", just2_txt)

    def test_iteration82_sast07_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler

        with tempfile.TemporaryDirectory() as td_sast7:
            r7 = Path(td_sast7)
            src = r7 / "src"
            src.mkdir()
            # 1. Explicit allowlist field picking passes static framework binder check
            (src / "safe.ts").write_text(
                "export const mk = (req: any, User: any) => User.create({ email: req.body.email, name: req.body.name });\n",
                encoding="utf-8",
            )
            v_pass, f_pass, _, _ = evaluate_sast07_framework_binding(r7)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for allowlisted fields, got {f_pass}")

            # 2. Multi-language unrestricted binders trigger SAST-07 via Semgrep
            (src / "bad.ts").write_text("export const up = (req: any, User: any) => User.update(req.body, { where: { id: 1 } });\n", encoding="utf-8")
            (src / "bad.py").write_text("class UserForm:\n    class Meta:\n        fields = '__all__'\n", encoding="utf-8")
            (src / "Bad.java").write_text("class C { void f(Object dto, Object ent) { BeanUtils.copyProperties(dto, ent); } }\n", encoding="utf-8")
            (src / "bad.go").write_text("package p\nfunc h(c any, u any) { c.ShouldBindJSON(&u) }\n", encoding="utf-8")
            v_fail, f_fail, sarif_fail, _ = evaluate_sast07_framework_binding(r7)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("bad.ts", "bad.py", "Bad.java", "bad.go"):
                self.assertIn(fname, joined, f"Missing SAST-07 finding for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(sarif_fail), 4)

            # 3. Active update + read-back verification (mock vulnerable vs hardened endpoints)
            class _MassAssignHandler(BaseHTTPRequestHandler):
                vulnerable = True
                role_stored = "customer"

                def log_message(self, fmt, *args):
                    pass

                def do_POST(self):
                    ln = int(self.headers.get("Content-Length", "0"))
                    body = json.loads(self.rfile.read(ln).decode() or "{}")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    if self.path.endswith("/login"):
                        self.wfile.write(json.dumps({"authentication": {"token": "tok-1"}}).encode())
                        return
                    if type(self).vulnerable and "role" in body:
                        type(self).role_stored = body["role"]
                    self.wfile.write(json.dumps({"data": {"id": 1, "role": type(self).role_stored}}).encode())

                def do_PUT(self):
                    ln = int(self.headers.get("Content-Length", "0"))
                    body = json.loads(self.rfile.read(ln).decode() or "{}")
                    if type(self).vulnerable and "role" in body:
                        type(self).role_stored = body["role"]
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"data": {"id": 1, "role": type(self).role_stored}}).encode())

                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"data": {"id": 1, "role": type(self).role_stored}}).encode())

            sarif_tmp = Path(td_sast7) / "out.sarif"
            sarif_tmp.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": []}]}), encoding="utf-8")
            srv = ThreadingHTTPServer(("127.0.0.1", 0), _MassAssignHandler)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                _MassAssignHandler.vulnerable = True
                _MassAssignHandler.role_stored = "customer"
                hit_vuln = evaluate_sast07_mass_assignment_probe(
                    f"http://127.0.0.1:{port}",
                    dast_sarif_path=Path(td_sast7) / "missing.sarif",
                    sarif_out=sarif_tmp,
                )
                self.assertIsNotNone(hit_vuln)
                self.assertIn("Update+ReadBack", hit_vuln)
                sdata = json.loads(sarif_tmp.read_text(encoding="utf-8"))
                self.assertEqual(sdata["runs"][0]["results"][0]["ruleId"], "CASA3-SAST-07-active-mass-assignment")

                _MassAssignHandler.vulnerable = False
                _MassAssignHandler.role_stored = "customer"
                hit_safe = evaluate_sast07_mass_assignment_probe(
                    f"http://127.0.0.1:{port}",
                    dast_sarif_path=Path(td_sast7) / "missing.sarif",
                    sarif_out=sarif_tmp,
                )
                self.assertIsNone(hit_safe)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 12/61: SAST-07 (Iteração SDD 082)", just2_txt)

    def test_iteration83_sast08_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sast8:
            r8 = Path(td_sast8)
            src = r8 / "src"
            src.mkdir()
            # 1. Parameterized queries (ORM replacements / SQL placeholders) -> PASS
            (src / "safe_sql.ts").write_text(
                "export const q = (req: any, seq: any) => seq.query('SELECT * FROM users WHERE id = :id', { replacements: { id: req.params.id } });\n",
                encoding="utf-8",
            )
            (src / "safe_sql.py").write_text(
                "def q(request, cur):\n    cur.execute('SELECT * FROM users WHERE id = %s', (request.args.get('id'),))\n",
                encoding="utf-8",
            )
            v_pass, f_pass, _, _ = evaluate_sast08_sql_injection(r8)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for parameterized queries, got {f_pass}")

            # 2. Multi-language SQL/NoSQL injection taint flows -> FAIL
            (src / "sqli.ts").write_text(
                "export const s = (req: any, models: any) => {\n  const q = 'SELECT * FROM Products WHERE name = ' + req.query.q;\n  return models.sequelize.query(q);\n};\n",
                encoding="utf-8",
            )
            (src / "sqli.py").write_text(
                "def s(request, cursor):\n    sql = f\"SELECT * FROM users WHERE name = '{request.args['u']}'\"\n    cursor.execute(sql)\n",
                encoding="utf-8",
            )
            (src / "Sqli.java").write_text(
                'class Sqli { void q(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) throws Exception { String u = req.getParameter("u"); st.executeQuery("SELECT * FROM u WHERE n=" + u); } }\n',
                encoding="utf-8",
            )
            (src / "sqli.go").write_text(
                'package p\nfunc h(r *http.Request, db *sql.DB) { q := "SELECT * FROM u WHERE n=" + r.URL.Query().Get("n"); db.Query(q) }\n',
                encoding="utf-8",
            )
            v_fail, f_fail, sarif_fail, _ = evaluate_sast08_sql_injection(r8)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("sqli.ts", "sqli.py", "Sqli.java", "sqli.go"):
                self.assertIn(fname, joined, f"Missing SAST-08 taint hit for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(sarif_fail), 4)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 13/61: SAST-08 (Iteração SDD 083)", just2_txt)

    def test_iteration84_sast09_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sast9:
            r9 = Path(td_sast9)
            src = r9 / "src"
            src.mkdir()
            # 1. SafeLoader / allowlisted classes / ObjectInputFilter / HMAC-verified -> PASS
            (src / "safe_deser.py").write_text(
                "import yaml, hmac, pickle\n"
                "cfg = yaml.load(raw, Loader=yaml.SafeLoader)\n"
                "def verified(sig, exp, blob):\n    if hmac.compare_digest(sig, exp):\n        return pickle.loads(blob)\n",
                encoding="utf-8",
            )
            (src / "SafeDeser.java").write_text(
                "import java.io.*;\nclass SafeDeser { Object read(InputStream in) throws Exception { ObjectInputStream ois = new ObjectInputStream(in); ois.setObjectInputFilter(info -> ObjectInputFilter.Status.ALLOWED); return ois.readObject(); } }\n",
                encoding="utf-8",
            )
            (src / "safe_deser.php").write_text(
                '<?php $x = unserialize($raw, ["allowed_classes" => false]);\n',
                encoding="utf-8",
            )
            v_pass, f_pass, _, _ = evaluate_sast09_deserialization(r9)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for guarded deserialization, got {f_pass}")

            # 2. Unguarded deserialization sinks across TS, Python, Java, PHP, C# -> FAIL
            (src / "bad_deser.ts").write_text("export const parse = (data: string) => yaml.load(data);\n", encoding="utf-8")
            (src / "bad_deser.py").write_text("import pickle\ndef load_raw(b): return pickle.loads(b)\n", encoding="utf-8")
            (src / "BadDeser.java").write_text("import java.io.*;\nclass BadDeser { Object read(InputStream in) throws Exception { return new ObjectInputStream(in).readObject(); } }\n", encoding="utf-8")
            (src / "bad_deser.php").write_text("<?php $u = unserialize($_POST['data']);\n", encoding="utf-8")
            (src / "BadDeser.cs").write_text("using System.Runtime.Serialization.Formatters.Binary;\nclass B { void F() { var bf = new BinaryFormatter(); } }\n", encoding="utf-8")
            v_fail, f_fail, sarif_fail, _ = evaluate_sast09_deserialization(r9)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("bad_deser.ts", "bad_deser.py", "BadDeser.java", "bad_deser.php", "BadDeser.cs"):
                self.assertIn(fname, joined, f"Missing SAST-09 hit for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(sarif_fail), 5)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 14/61: SAST-09 (Iteração SDD 084)", just2_txt)

    def test_iteration85_sast10_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sast10:
            r10 = Path(td_sast10)
            src = r10 / "src"
            src.mkdir()
            # 1. Static literal command / constant module loads (no untrusted taint flow) -> PASS
            (src / "safe_exec.ts").write_text(
                "import { execFile } from 'child_process';\nconst fs = require('fs');\nexport const ls = (req: any) => execFile('ls', ['-la']);\n",
                encoding="utf-8",
            )
            (src / "SafeRefl.java").write_text(
                'class SafeRefl { Class<?> load() throws Exception { return Class.forName("com.example.SafePlugin"); } }\n',
                encoding="utf-8",
            )
            v_pass, f_pass, _, _ = evaluate_sast10_dynamic_execution(r10)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for static literals, got {f_pass}")

            # 2. Tainted request inputs into eval, Python importlib reflection, Java Class.forName, Go exec.Command -> FAIL
            (src / "rce_bad.ts").write_text(
                "export const run = (req: any) => { const expr = req.body.expr; return eval(expr); };\n",
                encoding="utf-8",
            )
            (src / "rce_bad.py").write_text(
                "import importlib\ndef load_mod(request):\n    m = request.args.get('plugin')\n    return importlib.import_module(m)\n",
                encoding="utf-8",
            )
            (src / "RceBad.java").write_text(
                'class RceBad { Class<?> dyn(javax.servlet.http.HttpServletRequest req) throws Exception { String c = req.getParameter("cls"); return Class.forName(c); } }\n',
                encoding="utf-8",
            )
            (src / "rce_bad.go").write_text(
                'package p\nfunc h(r *http.Request) { cmd := r.URL.Query().Get("cmd"); exec.Command(cmd) }\n',
                encoding="utf-8",
            )
            v_fail, f_fail, sarif_fail, _ = evaluate_sast10_dynamic_execution(r10)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("rce_bad.ts", "rce_bad.py", "RceBad.java", "rce_bad.go"):
                self.assertIn(fname, joined, f"Missing SAST-10 taint hit for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(sarif_fail), 4)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 15/61: SAST-10 (Iteração SDD 085)", just2_txt)

    def test_iteration86_sast11_guide_tooling(self) -> None:
        with tempfile.TemporaryDirectory() as td_sast11:
            r11 = Path(td_sast11)
            src = r11 / "src"
            src.mkdir()
            # 1. Sanitized path components (basename / secure_filename / filepath.Base) -> PASS
            (src / "safe_path.ts").write_text(
                "import path from 'path';\nimport fs from 'fs';\nexport const read = (req: any) => fs.readFileSync(path.resolve('/srv/uploads', path.basename(req.params.file)));\n",
                encoding="utf-8",
            )
            (src / "safe_path.py").write_text(
                "import os\ndef save(request):\n    fn = os.path.basename(request.args['f'])\n    return open('/srv/' + fn)\n",
                encoding="utf-8",
            )
            (src / "safe_path.go").write_text(
                'package p\nimport ("os"; "path/filepath")\nfunc rd(r *http.Request) { p := filepath.Base(r.URL.Query().Get("f")); os.ReadFile(p) }\n',
                encoding="utf-8",
            )
            v_pass, f_pass, _, _ = evaluate_sast11_path_traversal(r11)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for sanitized paths, got {f_pass}")

            # 2. Unsanitized path construction & Zip Slip across TS, Python, Java, Go -> FAIL
            (src / "trav_bad.ts").write_text(
                "import fs from 'fs';\nexport const dl = (req: any) => fs.readFileSync('/srv/' + req.query.file);\n",
                encoding="utf-8",
            )
            (src / "trav_bad.py").write_text(
                "def extract_zip(zipinfo):\n    target = '/var/app/' + zipinfo.filename\n    return open(target, 'wb')\n",
                encoding="utf-8",
            )
            (src / "TravBad.java").write_text(
                'import java.io.*; import java.util.zip.*;\nclass TravBad { File unzip(ZipEntry entry) { File dst = new File("/tmp/" + entry.getName()); return dst; } }\n',
                encoding="utf-8",
            )
            (src / "trav_bad.go").write_text(
                'package p\nfunc dl(r *http.Request) { f := "/var/www/" + r.URL.Query().Get("p"); os.Open(f) }\n',
                encoding="utf-8",
            )
            v_fail, f_fail, sarif_fail, _ = evaluate_sast11_path_traversal(r11)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("trav_bad.ts", "trav_bad.py", "TravBad.java", "trav_bad.go"):
                self.assertIn(fname, joined, f"Missing SAST-11 taint hit for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(sarif_fail), 4)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 16/61: SAST-11 (Iteração SDD 086)", just2_txt)

    def test_iteration87_sast12_guide_tooling(self) -> None:
        self.assertTrue(Path(TRIVY_BIN).exists(), f"trivy binary not found at {TRIVY_BIN}")
        with tempfile.TemporaryDirectory() as td_sast12:
            r12 = Path(td_sast12)
            (r12 / "src").mkdir()
            # 1. Clean repo using SecretsManagerClient SDK -> 0 SAST-12 findings
            (r12 / "package.json").write_text('{"dependencies": {"@aws-sdk/client-secrets-manager": "^3.0.0"}}', encoding="utf-8")
            (r12 / "src" / "secrets.ts").write_text(
                "import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';\nexport const client = new SecretsManagerClient({});\n",
                encoding="utf-8",
            )
            f_clean, _, sdk_ok = evaluate_sast12_secrets_management_and_iac(r12, run_docker=False)
            self.assertEqual(f_clean, [])
            self.assertIn("SecretsManagerClient", sdk_ok)

            # 2. Hardcoded server-side GitHub/Stripe/AWS secret & Dockerfile secret -> caught by Trivy + IaC inspector
            (r12 / "Dockerfile").write_text("FROM node:20\nENV JWT_SECRET=SuperHardcodedJwtSecret999\n", encoding="utf-8")
            (r12 / ".env").write_text("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", encoding="utf-8")
            f_bad, s_bad, _ = evaluate_sast12_secrets_management_and_iac(r12, run_docker=False)
            joined = "\n".join(f_bad)
            self.assertIn(".env", joined)
            self.assertTrue(any("[TRIVY" in f for f in f_bad), f"Expected Trivy secret detection in:\n{joined}")
            self.assertTrue((ROOT_DIR / "casa-assessment" / "output" / "trivy-sast12.sarif").exists())
            self.assertGreaterEqual(len(s_bad), 2)

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 17/61: SAST-12 (Iteração SDD 087)", just2_txt)

    def test_iteration88_sast13_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler

        with tempfile.TemporaryDirectory() as td_sast13:
            r13 = Path(td_sast13)
            src = r13 / "src"
            src.mkdir()
            # 1. Hashed / masked log values -> PASS
            (src / "safe_log.ts").write_text(
                "export const logTok = (req: any, logger: any) => logger.info(sha256(req.headers.authorization));\n",
                encoding="utf-8",
            )
            (src / "safe_log.py").write_text(
                "import hashlib, logging\ndef lg(password):\n    logging.info(hashlib.sha256(password).hexdigest())\n",
                encoding="utf-8",
            )
            v_pass, f_pass, _, _ = evaluate_sast13_sensitive_logging(r13)
            self.assertEqual(v_pass, "PASS", f"Expected PASS for hashed logging, got {f_pass}")

            # 2. Unmasked sensitive logging taint across TS, Python, Java, Go -> FAIL
            (src / "log_bad.ts").write_text(
                "export const lg = (req: any, logger: any) => { const p = req.body.password; logger.info(p); };\n",
                encoding="utf-8",
            )
            (src / "log_bad.py").write_text(
                "import logging\ndef lg(authorization):\n    logging.error(authorization)\n",
                encoding="utf-8",
            )
            (src / "LogBad.java").write_text(
                "class LogBad { void lg(String cardNumber) { System.out.println(cardNumber); } }\n",
                encoding="utf-8",
            )
            (src / "log_bad.go").write_text(
                'package p\nimport "log"\nfunc lg(refreshToken string) { log.Printf("%s", refreshToken) }\n',
                encoding="utf-8",
            )
            v_fail, f_fail, sarif_fail, _ = evaluate_sast13_sensitive_logging(r13)
            self.assertEqual(v_fail, "FAIL")
            joined = "\n".join(f_fail)
            for fname in ("log_bad.ts", "log_bad.py", "LogBad.java", "log_bad.go"):
                self.assertIn(fname, joined, f"Missing SAST-13 taint hit for {fname} in:\n{joined}")
            self.assertGreaterEqual(len(sarif_fail), 4)

            # 3. Scripted Canary Auth/Token/Payment Replay Harness -> FAIL on leaked query/header, PASS on clean logs
            log_dir = r13 / "logs"
            log_dir.mkdir()
            log_file = log_dir / "access.log"
            sarif_tmp = r13 / "sast13.sarif"
            sarif_tmp.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": []}]}), encoding="utf-8")

            class _CanaryHandler(BaseHTTPRequestHandler):
                leak = True

                def log_message(self, fmt, *args):
                    pass

                def _handle(self):
                    if type(self).leak:
                        auth = self.headers.get("Authorization", "")
                        log_file.write_text(f"GET {self.path} auth={auth}\n", encoding="utf-8")
                    self.send_response(200)
                    self.end_headers()

                def do_GET(self):
                    self._handle()

                def do_POST(self):
                    ln = int(self.headers.get("Content-Length", "0"))
                    _ = self.rfile.read(ln)
                    self._handle()

            srv = ThreadingHTTPServer(("127.0.0.1", 0), _CanaryHandler)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                _CanaryHandler.leak = True
                hits_leak = evaluate_sast13_canary_log_replay(f"http://127.0.0.1:{port}", r13, sarif_out=sarif_tmp)
                self.assertGreaterEqual(len(hits_leak), 1)
                sdata = json.loads(sarif_tmp.read_text(encoding="utf-8"))
                self.assertEqual(sdata["runs"][0]["results"][0]["ruleId"], "CASA3-SAST-13-canary-log-leak")

                _CanaryHandler.leak = False
                log_file.write_text("clean request hashed_token=abc123\n", encoding="utf-8")
                hits_clean = evaluate_sast13_canary_log_replay(f"http://127.0.0.1:{port}", r13, sarif_out=sarif_tmp)
                self.assertEqual(hits_clean, [])
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 18/61: SAST-13 (Iteração SDD 088)", just2_txt)

    def test_iteration89_tls01_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        import socket
        import ssl
        import subprocess
        from casa_audit.scanner import evaluate_tls01_transport_enforcement

        with tempfile.TemporaryDirectory() as td_tls1:
            tdp = Path(td_tls1)
            cert, key = tdp / "cert.pem", tdp / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )

            class _TlsHandler(BaseHTTPRequestHandler):
                def log_message(self, fmt, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

            class _HttpModeHandler(BaseHTTPRequestHandler):
                redirect_to_https = True
                tls_port_num = 443

                def log_message(self, fmt, *args):
                    pass

                def do_GET(self):
                    if type(self).redirect_to_https:
                        self.send_response(301)
                        self.send_header("Location", f"https://127.0.0.1:{type(self).tls_port_num}{self.path}")
                        self.end_headers()
                    else:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"cleartext leak")

            tls_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TlsHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
            tls_srv.socket = ctx.wrap_socket(tls_srv.socket, server_side=True)
            tls_port = tls_srv.server_address[1]

            http_srv = ThreadingHTTPServer(("127.0.0.1", 0), _HttpModeHandler)
            http_port = http_srv.server_address[1]
            _HttpModeHandler.tls_port_num = tls_port

            t_tls = threading.Thread(target=tls_srv.serve_forever, daemon=True)
            t_http = threading.Thread(target=http_srv.serve_forever, daemon=True)
            t_tls.start()
            t_http.start()
            try:
                # 1. HTTPS TLS server via official testssl.sh + 301 redirect to https://127.0.0.1 -> PASS
                _HttpModeHandler.redirect_to_https = True
                res_pass = evaluate_tls01_transport_enforcement(
                    f"https://127.0.0.1:{tls_port}",
                    raw_json_path=tdp / "raw_pass.json",
                    cleartext_port_override=http_port,
                )
                self.assertEqual(res_pass["verdict"], "PASS", f"Expected PASS, got {res_pass}")
                self.assertTrue(res_pass["testssl"]["executed"])
                self.assertTrue(res_pass["testssl"]["handshakeOk"])
                self.assertTrue((tdp / "raw_pass.json").exists())

                # 2. Same TLS server + HTTP 200 cleartext response without redirect -> FAIL
                _HttpModeHandler.redirect_to_https = False
                res_leak = evaluate_tls01_transport_enforcement(
                    f"https://127.0.0.1:{tls_port}",
                    raw_json_path=tdp / "raw_leak.json",
                    cleartext_port_override=http_port,
                )
                self.assertEqual(res_leak["verdict"], "FAIL")
                self.assertTrue(any("cleartext" in v for v in res_leak["violations"]))

                # 3. Cleartext http:// declared target + closed TLS port -> FAIL with testssl.sh scanProblem
                closed_sock = socket.socket()
                closed_sock.bind(("127.0.0.1", 0))
                closed_port = closed_sock.getsockname()[1]
                closed_sock.close()
                res_closed = evaluate_tls01_transport_enforcement(
                    f"http://127.0.0.1:{http_port}",
                    raw_json_path=tdp / "raw_closed.json",
                    tls_port_override=closed_port,
                )
                self.assertEqual(res_closed["verdict"], "FAIL")
                self.assertFalse(res_closed["testssl"]["handshakeOk"])
                self.assertIsNotNone(res_closed["testssl"]["scanProblem"])
            finally:
                tls_srv.shutdown()
                tls_srv.server_close()
                http_srv.shutdown()
                http_srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 19/61: TLS-01 (Iteração SDD 089)", just2_txt)

    def test_iteration90_tls02_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        import ssl
        import subprocess
        import warnings
        from casa_audit.scanner import evaluate_tls02_protocol_enforcement

        with tempfile.TemporaryDirectory() as td_tls2:
            tdp = Path(td_tls2)
            cert, key = tdp / "cert.pem", tdp / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )

            class _OkHandler(BaseHTTPRequestHandler):
                def log_message(self, fmt, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

            # 1. Modern TLS 1.2/1.3 only -> PASS via official testssl.sh -p
            srv_modern = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
            ctx_modern = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx_modern.load_cert_chain(certfile=str(cert), keyfile=str(key))
            ctx_modern.minimum_version = ssl.TLSVersion.TLSv1_2
            srv_modern.socket = ctx_modern.wrap_socket(srv_modern.socket, server_side=True)
            port_modern = srv_modern.server_address[1]
            threading.Thread(target=srv_modern.serve_forever, daemon=True).start()

            # 2. Legacy TLS 1.0/1.1 enabled server (SECLEVEL=0) -> FAIL via official testssl.sh -p
            srv_legacy = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx_legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx_legacy.load_cert_chain(certfile=str(cert), keyfile=str(key))
                ctx_legacy.set_ciphers("ALL:@SECLEVEL=0")
                ctx_legacy.minimum_version = ssl.TLSVersion.TLSv1
            srv_legacy.socket = ctx_legacy.wrap_socket(srv_legacy.socket, server_side=True)
            port_legacy = srv_legacy.server_address[1]
            threading.Thread(target=srv_legacy.serve_forever, daemon=True).start()

            # 3. Cleartext HTTP only -> FAIL (no TLS 1.2/1.3 offered)
            srv_http = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
            port_http = srv_http.server_address[1]
            threading.Thread(target=srv_http.serve_forever, daemon=True).start()

            try:
                res_modern = evaluate_tls02_protocol_enforcement(
                    f"https://127.0.0.1:{port_modern}",
                    raw_json_path=tdp / "tls02_modern.json",
                )
                self.assertEqual(res_modern["verdict"], "PASS", f"Expected PASS for TLS 1.2/1.3 only, got {res_modern}")
                self.assertEqual(res_modern["deprecatedOffered"], [])
                self.assertIn("TLS 1.2", res_modern["modernOffered"])
                self.assertEqual(res_modern["protocols"]["SSLv2"], "not offered")
                self.assertEqual(res_modern["protocols"]["SSLv3"], "not offered")
                self.assertEqual(res_modern["protocols"]["TLS 1.0"], "not offered")
                self.assertEqual(res_modern["protocols"]["TLS 1.1"], "not offered")

                res_legacy = evaluate_tls02_protocol_enforcement(
                    f"https://127.0.0.1:{port_legacy}",
                    raw_json_path=tdp / "tls02_legacy.json",
                )
                self.assertEqual(res_legacy["verdict"], "FAIL", f"Expected FAIL for TLS 1.0/1.1 offered, got {res_legacy}")
                self.assertIn("TLS 1.0", res_legacy["deprecatedOffered"])
                self.assertIn("TLS 1.1", res_legacy["deprecatedOffered"])

                res_http = evaluate_tls02_protocol_enforcement(
                    f"http://127.0.0.1:{port_http}",
                    raw_json_path=tdp / "tls02_http.json",
                )
                self.assertEqual(res_http["verdict"], "FAIL")
                self.assertEqual(res_http["modernOffered"], [])
            finally:
                srv_modern.shutdown()
                srv_modern.server_close()
                srv_legacy.shutdown()
                srv_legacy.server_close()
                srv_http.shutdown()
                srv_http.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 20/61: TLS-02 (Iteração SDD 090)", just2_txt)

    def test_iteration91_tls03_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        import ssl
        import subprocess
        from casa_audit.scanner import evaluate_tls03_cipher_enforcement

        with tempfile.TemporaryDirectory() as td_tls3:
            tdp = Path(td_tls3)
            cert, key = tdp / "cert.pem", tdp / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )

            class _OkHandler(BaseHTTPRequestHandler):
                def log_message(self, fmt, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

            def _mk_tls_srv(cipher_spec: str, min_v: ssl.TLSVersion, max_v: ssl.TLSVersion):
                srv = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
                ctx.set_ciphers(cipher_spec)
                ctx.minimum_version = min_v
                ctx.maximum_version = max_v
                srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                return srv, srv.server_address[1]

            # 1. Hardened ECDHE AEAD FS server -> PASS via testssl.sh --ssl-native -s -f
            srv_hard, port_hard = _mk_tls_srv(
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305",
                ssl.TLSVersion.TLSv1_2,
                ssl.TLSVersion.TLSv1_3,
            )
            # 2. Static-RSA non-FS TLS 1.2 server -> FAIL via testssl.sh (STRONG_NOFS + zero FS)
            srv_nofs, port_nofs = _mk_tls_srv(
                "AES128-GCM-SHA256:AES256-GCM-SHA384",
                ssl.TLSVersion.TLSv1_2,
                ssl.TLSVersion.TLSv1_2,
            )
            # 3. Legacy CBC-SHA1 server -> FAIL via testssl.sh (cipherlist_OBSOLETED offered)
            srv_cbc, port_cbc = _mk_tls_srv(
                "ECDHE-RSA-AES128-SHA:AES128-SHA:@SECLEVEL=0",
                ssl.TLSVersion.TLSv1_2,
                ssl.TLSVersion.TLSv1_2,
            )
            # 4. Cleartext HTTP only -> FAIL (zero strong FS suites)
            srv_http = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
            port_http = srv_http.server_address[1]
            threading.Thread(target=srv_http.serve_forever, daemon=True).start()

            try:
                res_hard = evaluate_tls03_cipher_enforcement(
                    f"https://127.0.0.1:{port_hard}",
                    raw_json_path=tdp / "tls03_hard.json",
                )
                self.assertEqual(res_hard["verdict"], "PASS", f"Expected PASS, got {res_hard}")
                self.assertEqual(res_hard["cipherAudit"]["bannedSuitesOffered"], [])
                self.assertEqual(res_hard["cipherAudit"]["nonForwardSecrecyTls12Offered"], [])
                self.assertTrue(len(res_hard["cipherAudit"]["strongForwardSecrecyOffered"]) >= 1)

                res_nofs = evaluate_tls03_cipher_enforcement(
                    f"https://127.0.0.1:{port_nofs}",
                    raw_json_path=tdp / "tls03_nofs.json",
                )
                self.assertEqual(res_nofs["verdict"], "FAIL", f"Expected FAIL on non-FS RSA, got {res_nofs}")
                self.assertTrue(len(res_nofs["cipherAudit"]["nonForwardSecrecyTls12Offered"]) >= 1)

                res_cbc = evaluate_tls03_cipher_enforcement(
                    f"https://127.0.0.1:{port_cbc}",
                    raw_json_path=tdp / "tls03_cbc.json",
                )
                self.assertEqual(res_cbc["verdict"], "FAIL", f"Expected FAIL on CBC-SHA1, got {res_cbc}")
                self.assertTrue(any("OBSOLETED" in x for x in res_cbc["cipherAudit"]["bannedSuitesOffered"]))

                res_http = evaluate_tls03_cipher_enforcement(
                    f"http://127.0.0.1:{port_http}",
                    raw_json_path=tdp / "tls03_http.json",
                )
                self.assertEqual(res_http["verdict"], "FAIL")
                self.assertEqual(res_http["cipherAudit"]["strongForwardSecrecyOffered"], [])
            finally:
                for s in (srv_hard, srv_nofs, srv_cbc, srv_http):
                    s.shutdown()
                    s.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 21/61: TLS-03 (Iteração SDD 091)", just2_txt)

    def test_iteration92_tls04_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        import ssl
        import subprocess
        from casa_audit.scanner import evaluate_tls04_certificate_validation

        with tempfile.TemporaryDirectory() as td_tls4:
            tdp = Path(td_tls4)
            ca_k, ca_c = tdp / "ca.key", tdp / "ca.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(ca_k), "-out", str(ca_c), "-days", "365",
                    "-subj", "/CN=TestRootCA",
                ],
                check=True,
                capture_output=True,
            )

            def _issue_srv_cert(prefix: str, cn: str, san: str, days: int, self_signed: bool = False):
                sk = tdp / f"{prefix}.key"
                sc = tdp / f"{prefix}.pem"
                if self_signed:
                    subprocess.run(
                        [
                            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(sk), "-out", str(sc), "-days", str(days),
                            "-subj", f"/CN={cn}", "-addext", f"subjectAltName={san}",
                        ],
                        check=True,
                        capture_output=True,
                    )
                    return sc, sk
                csr = tdp / f"{prefix}.csr"
                ext = tdp / f"{prefix}.ext"
                ext.write_text(
                    f"subjectAltName={san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
                    encoding="utf-8",
                )
                subprocess.run(
                    ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(sk), "-out", str(csr), "-subj", f"/CN={cn}"],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_c), "-CAkey", str(ca_k), "-CAcreateserial", "-out", str(sc), "-days", str(days), "-extfile", str(ext)],
                    check=True,
                    capture_output=True,
                )
                return sc, sk

            class _OkHandler(BaseHTTPRequestHandler):
                def log_message(self, fmt, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

            def _start_srv(cert_p: Path, key_p: Path):
                srv = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
                srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                return srv, srv.server_address[1]

            c_ok, k_ok = _issue_srv_cert("ok", "127.0.0.1", "DNS:localhost,IP:127.0.0.1", 45)
            c_short, k_short = _issue_srv_cert("short", "127.0.0.1", "DNS:localhost,IP:127.0.0.1", 5)
            c_mismatch, k_mismatch = _issue_srv_cert("mismatch", "wrong.example.org", "DNS:wrong.example.org", 45)
            c_self, k_self = _issue_srv_cert("self", "127.0.0.1", "DNS:localhost,IP:127.0.0.1", 45, self_signed=True)

            s_ok, p_ok = _start_srv(c_ok, k_ok)
            s_short, p_short = _start_srv(c_short, k_short)
            s_mismatch, p_mismatch = _start_srv(c_mismatch, k_mismatch)
            s_self, p_self = _start_srv(c_self, k_self)
            s_http = ThreadingHTTPServer(("127.0.0.1", 0), _OkHandler)
            p_http = s_http.server_address[1]
            threading.Thread(target=s_http.serve_forever, daemon=True).start()

            try:
                # 1. Valid CA-signed cert >= 30d -> PASS without warnings
                r_ok = evaluate_tls04_certificate_validation(
                    f"https://127.0.0.1:{p_ok}",
                    raw_json_path=tdp / "raw_ok.json",
                    extra_ca_file=ca_c,
                )
                self.assertEqual(r_ok["verdict"], "PASS", f"Expected PASS, got {r_ok}")
                self.assertTrue(r_ok["certAudit"]["chainTrustedToPublicRoot"])
                self.assertTrue(r_ok["certAudit"]["hostnameMatches"])
                self.assertTrue(r_ok["certAudit"]["notExpired"])
                self.assertGreaterEqual(r_ok["certAudit"]["remainingDays"], 30)

                # 2. Valid CA-signed short-lived cert (<30d) -> PASS + informational warning
                r_short = evaluate_tls04_certificate_validation(
                    f"https://127.0.0.1:{p_short}",
                    raw_json_path=tdp / "raw_short.json",
                    extra_ca_file=ca_c,
                )
                self.assertEqual(r_short["verdict"], "PASS", f"Expected PASS (<30d informational), got {r_short}")
                self.assertLess(r_short["certAudit"]["remainingDays"], 30)
                self.assertTrue(any("< 30 days" in w for w in r_short["certAudit"]["warnings"]))

                # 3. Hostname mismatch -> FAIL
                r_mismatch = evaluate_tls04_certificate_validation(
                    f"https://127.0.0.1:{p_mismatch}",
                    raw_json_path=tdp / "raw_mismatch.json",
                    extra_ca_file=ca_c,
                )
                self.assertEqual(r_mismatch["verdict"], "FAIL")
                self.assertFalse(r_mismatch["certAudit"]["hostnameMatches"])

                # 4. Self-signed / untrusted CA (no extra_ca_file) -> FAIL
                r_self = evaluate_tls04_certificate_validation(
                    f"https://127.0.0.1:{p_self}",
                    raw_json_path=tdp / "raw_self.json",
                )
                self.assertEqual(r_self["verdict"], "FAIL")
                self.assertFalse(r_self["certAudit"]["chainTrustedToPublicRoot"])

                # 5. Cleartext HTTP -> FAIL quickly
                r_http = evaluate_tls04_certificate_validation(
                    f"http://127.0.0.1:{p_http}",
                    raw_json_path=tdp / "raw_http.json",
                )
                self.assertEqual(r_http["verdict"], "FAIL")
                self.assertFalse(r_http["certAudit"]["present"])
            finally:
                for srv in (s_ok, s_short, s_mismatch, s_self, s_http):
                    srv.shutdown()
                    srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 22/61: TLS-04 (Iteração SDD 092)", just2_txt)

    def test_iteration93_tls05_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        import ssl
        import subprocess
        from casa_audit.scanner import evaluate_tls05_hsts_enforcement

        with tempfile.TemporaryDirectory() as td_tls5:
            tdp = Path(td_tls5)
            cert, key = tdp / "cert.pem", tdp / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )

            class _HstsHandler(BaseHTTPRequestHandler):
                hsts_header = "max-age=31536000; includeSubDomains; preload"

                def log_message(self, fmt, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    if type(self).hsts_header:
                        self.send_header("Strict-Transport-Security", type(self).hsts_header)
                    self.end_headers()
                    self.wfile.write(b"ok")

            srv_tls = ThreadingHTTPServer(("127.0.0.1", 0), _HstsHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
            srv_tls.socket = ctx.wrap_socket(srv_tls.socket, server_side=True)
            tls_port = srv_tls.server_address[1]
            threading.Thread(target=srv_tls.serve_forever, daemon=True).start()

            srv_http = ThreadingHTTPServer(("127.0.0.1", 0), _HstsHandler)
            http_port = srv_http.server_address[1]
            threading.Thread(target=srv_http.serve_forever, daemon=True).start()

            try:
                # 1. HTTPS with max-age=31536000 -> PASS via testssl.sh -h + endpoint probes
                _HstsHandler.hsts_header = "max-age=31536000; includeSubDomains; preload"
                r_pass = evaluate_tls05_hsts_enforcement(
                    f"https://127.0.0.1:{tls_port}",
                    raw_json_path=tdp / "hsts_pass.json",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertGreaterEqual(r_pass["HSTS_time"], 31536000)
                self.assertTrue(r_pass["testsslHsts"]["offered"])
                self.assertTrue(r_pass["testsslHsts"]["includeSubDomains"])

                # 2. HTTPS with weak max-age=600 (< 31536000) -> FAIL
                _HstsHandler.hsts_header = "max-age=600"
                r_low = evaluate_tls05_hsts_enforcement(
                    f"https://127.0.0.1:{tls_port}",
                    raw_json_path=tdp / "hsts_low.json",
                )
                self.assertEqual(r_low["verdict"], "FAIL")
                self.assertEqual(r_low["HSTS_time"], 600)

                # 3. HTTPS missing HSTS header -> FAIL
                _HstsHandler.hsts_header = ""
                r_none = evaluate_tls05_hsts_enforcement(
                    f"https://127.0.0.1:{tls_port}",
                    raw_json_path=tdp / "hsts_none.json",
                )
                self.assertEqual(r_none["verdict"], "FAIL")
                self.assertFalse(r_none["testsslHsts"]["offered"])

                # 4. Cleartext HTTP even with HSTS header -> FAIL (RFC 6797 §7.2)
                _HstsHandler.hsts_header = "max-age=31536000; includeSubDomains"
                r_http = evaluate_tls05_hsts_enforcement(
                    f"http://127.0.0.1:{http_port}",
                    raw_json_path=tdp / "hsts_http.json",
                )
                self.assertEqual(r_http["verdict"], "FAIL")
                self.assertTrue(any("cleartext HTTP" in v for v in r_http["violations"]))
            finally:
                srv_tls.shutdown()
                srv_tls.server_close()
                srv_http.shutdown()
                srv_http.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 23/61: TLS-05 (Iteração SDD 093)", just2_txt)

    def test_iteration94_tls06_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        import ssl
        import subprocess
        from casa_audit.scanner import evaluate_tls06_vulnerabilities

        with tempfile.TemporaryDirectory() as td_tls6:
            tdp = Path(td_tls6)
            cert, key = tdp / "cert.pem", tdp / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )

            class _OkTimeoutHandler(BaseHTTPRequestHandler):
                timeout = 2

                def log_message(self, fmt, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")

            srv_tls = ThreadingHTTPServer(("127.0.0.1", 0), _OkTimeoutHandler)
            srv_tls.daemon_threads = True
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
            ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305")
            srv_tls.socket = ctx.wrap_socket(srv_tls.socket, server_side=True)
            tls_port = srv_tls.server_address[1]
            threading.Thread(target=srv_tls.serve_forever, daemon=True).start()

            srv_http = ThreadingHTTPServer(("127.0.0.1", 0), _OkTimeoutHandler)
            srv_http.daemon_threads = True
            http_port = srv_http.server_address[1]
            threading.Thread(target=srv_http.serve_forever, daemon=True).start()

            try:
                # 1. Real testssl.sh -H -I -T -C + renegotiation/ROBOT on hardened TLS server -> PASS (~14s)
                r_pass = evaluate_tls06_vulnerabilities(
                    f"https://127.0.0.1:{tls_port}",
                    raw_json_path=tdp / "tls06_pass.json",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                vids = {v["id"] for v in r_pass["vulnAudit"]["vulnerabilities"]}
                for req_id in ("heartbleed", "CCS", "ticketbleed", "CRIME_TLS", "secure_renego", "ROBOT"):
                    self.assertIn(req_id, vids)
                self.assertEqual(r_pass["vulnAudit"]["highOrCriticalFindings"], [])

                # 2. Lower-severity (LOW/MEDIUM) finding remains informational -> PASS
                r_info = evaluate_tls06_vulnerabilities(
                    f"https://127.0.0.1:{tls_port}",
                    testssl_info={
                        "executed": True,
                        "version": "3.2.2",
                        "scanResult": [{
                            "vulnerabilities": [
                                {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable (OK)"},
                                {"id": "BREACH", "severity": "LOW", "finding": "HTTP compression"},
                            ]
                        }],
                    },
                )
                self.assertEqual(r_info["verdict"], "PASS")
                self.assertEqual(len(r_info["vulnAudit"]["informationalFindings"]), 1)

                # 3. HIGH / CRITICAL finding -> FAIL
                r_crit = evaluate_tls06_vulnerabilities(
                    f"https://127.0.0.1:{tls_port}",
                    testssl_info={
                        "executed": True,
                        "version": "3.2.2",
                        "scanResult": [{
                            "vulnerabilities": [
                                {"id": "ROBOT", "severity": "HIGH", "finding": "vulnerable"},
                                {"id": "heartbleed", "severity": "CRITICAL", "finding": "vulnerable"},
                            ]
                        }],
                    },
                )
                self.assertEqual(r_crit["verdict"], "FAIL")
                self.assertEqual(len(r_crit["vulnAudit"]["highOrCriticalFindings"]), 2)

                # 4. Cleartext HTTP -> FAIL quickly
                r_http = evaluate_tls06_vulnerabilities(
                    f"http://127.0.0.1:{http_port}",
                    raw_json_path=tdp / "tls06_http.json",
                )
                self.assertEqual(r_http["verdict"], "FAIL")
                self.assertEqual(r_http["vulnAudit"]["vulnerabilities"][0]["id"], "tls_endpoint_missing")
            finally:
                srv_tls.shutdown()
                srv_tls.server_close()
                srv_http.shutdown()
                srv_http.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 24/61: TLS-06 (Iteração SDD 094)", just2_txt)

    def test_iteration95_cfg01_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg01_directory_browsing

        class _Cfg01Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "clean"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                m = type(self).mode
                p = self.path.split("?", 1)[0]
                if m == "autoindex" and p.rstrip("/") == "/files":
                    body = (
                        b"<html><head><title>Index of /files</title></head>"
                        b'<body><h1>Index of /files</h1><a href="backup.sql">backup.sql</a></body></html>'
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if m == "s3" and p.rstrip("/") == "/public":
                    body = (
                        b'<?xml version="1.0" encoding="UTF-8"?>'
                        b"<ListBucketResult><Name>assets</Name><Contents><Key>secret.env</Key></Contents></ListBucketResult>"
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "application/xml")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p == "/":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>App Home</h1></body></html>")
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg01Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg1:
            tdp = Path(td_cfg1)
            try:
                # 1. Clean site with OWASP ZAP 2.17.0 spider -> PASS
                _Cfg01Handler.mode = "clean"
                r_clean = evaluate_cfg01_directory_browsing(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_clean.json",
                    sarif_out_path=tdp / "zap_clean.sarif",
                )
                self.assertEqual(r_clean["verdict"], "PASS", f"Expected PASS, got {r_clean}")
                self.assertTrue(r_clean["zap"]["executed"])
                self.assertTrue((tdp / "zap_clean.json").exists())
                self.assertTrue((tdp / "zap_clean.sarif").exists())

                # 2. Exposed HTML directory index -> FAIL detected via ZAP plugin 10033 + parser
                _Cfg01Handler.mode = "autoindex"
                r_auto = evaluate_cfg01_directory_browsing(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_auto.json",
                    sarif_out_path=tdp / "zap_auto.sarif",
                )
                self.assertEqual(r_auto["verdict"], "FAIL")
                self.assertIn("/files", r_auto["zapAlertsMatched"])
                self.assertEqual(r_auto["sarifResults"][0]["ruleId"], "CASA3-CFG-01")

                # 3. Exposed S3 ListBucketResult XML -> FAIL (reusing clean zap report for speed)
                _Cfg01Handler.mode = "s3"
                r_s3 = evaluate_cfg01_directory_browsing(
                    f"http://127.0.0.1:{port}",
                    zap_report=r_clean["zap"],
                )
                self.assertEqual(r_s3["verdict"], "FAIL")
                self.assertTrue(any("ListBucketResult" in f["format"] for f in r_s3["findings"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 25/61: CFG-01 (Iteração SDD 095)", just2_txt)

    def test_iteration96_cfg02_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg02_debug_modes

        class _Cfg02Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "hardened"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                m = type(self).mode
                p = self.path.split("?", 1)[0]
                if m == "vulnerable":
                    if p == "/actuator/env":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"activeProfiles":["dev"],"propertySources":[]}')
                        return
                    if p == "/console":
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html")
                        self.end_headers()
                        self.wfile.write(b"<html><title>Werkzeug Console</title><body>evalex interactive debugger</body></html>")
                        return
                # Hardened / SPA catch-all returns <app-root> cleanly without exposing debug payloads
                self.send_response(200 if p == "/" else 404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><app-root></app-root></body></html>")

            def do_POST(self):
                ln = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(ln)
                if type(self).mode == "vulnerable" and self.path == "/rest/user/login":
                    self.send_response(500)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body>You&#x27;re seeing this error because you have <code>DEBUG = True</code> in your Django settings</body></html>")
                    return
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"bad request"}')

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg02Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg2:
            tdp = Path(td_cfg2)
            try:
                # 1. Hardened / SPA site -> PASS via Nuclei 3.11.1 (0 findings, SARIF+JSONL created)
                _Cfg02Handler.mode = "hardened"
                r_pass = evaluate_cfg02_debug_modes(
                    f"http://127.0.0.1:{port}",
                    jsonl_out_path=tdp / "cfg02_pass.jsonl",
                    sarif_out_path=tdp / "cfg02_pass.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["nuclei"]["executed"])
                self.assertTrue((tdp / "cfg02_pass.sarif").exists())

                # 2. Vulnerable Spring Actuator + Werkzeug console + Django DEBUG=True -> FAIL
                _Cfg02Handler.mode = "vulnerable"
                r_fail = evaluate_cfg02_debug_modes(
                    f"http://127.0.0.1:{port}",
                    jsonl_out_path=tdp / "cfg02_fail.jsonl",
                    sarif_out_path=tdp / "cfg02_fail.sarif",
                )
                self.assertEqual(r_fail["verdict"], "FAIL")
                tids = {f["templateId"] for f in r_fail["findings"]}
                self.assertIn("casa3-cfg02-spring-actuator", tids)
                self.assertIn("casa3-cfg02-framework-consoles", tids)
                self.assertIn("casa3-cfg02-debug-traceback-markers", tids)
                self.assertTrue((tdp / "cfg02_fail.sarif").exists())
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 26/61: CFG-02 (Iteração SDD 096)", just2_txt)

    def test_iteration97_cfg03_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg03_version_disclosure

        class _Cfg03Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "clean"

            def log_message(self, fmt, *args):
                pass

            def version_string(self):
                return "nginx/1.24.0" if type(self).mode == "banner" else "AppGateway"

            def do_GET(self):
                m = type(self).mode
                p = self.path.split("?", 1)[0]
                if m == "banner":
                    self.send_response(200)
                    self.send_header("X-Powered-By", "Express")
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body>Hello</body></html>")
                    return
                if m == "body_tok" and p == "/":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body>Powered by Apache-Coyote/1.1</body></html>")
                    return
                self.send_response(200 if p == "/" else 404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>Clean</body></html>")

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg03Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg3:
            tdp = Path(td_cfg3)
            try:
                # 1. Clean headers and bodies -> PASS via OWASP ZAP 2.17.0
                _Cfg03Handler.mode = "clean"
                r_pass = evaluate_cfg03_version_disclosure(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c3_pass.json",
                    sarif_out_path=tdp / "zap_c3_pass.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["zap"]["executed"])

                # 2. Disclosed Server: nginx/1.24.0 + X-Powered-By: Express -> FAIL caught by ZAP 10036/10037 + crawler
                _Cfg03Handler.mode = "banner"
                r_banner = evaluate_cfg03_version_disclosure(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c3_banner.json",
                    sarif_out_path=tdp / "zap_c3_banner.sarif",
                )
                self.assertEqual(r_banner["verdict"], "FAIL")
                self.assertTrue({"10036", "10037"} & set(r_banner["zapPluginsMatched"]), f"Expected ZAP 10036/10037, got {r_banner}")
                tokens = {f["token"] for f in r_banner["findings"]}
                self.assertIn("nginx/1.24.0", tokens)

                # 3. Body version token Apache-Coyote/1.1 -> FAIL (reusing clean zap report)
                _Cfg03Handler.mode = "body_tok"
                r_body = evaluate_cfg03_version_disclosure(
                    f"http://127.0.0.1:{port}",
                    zap_report=r_pass["zap"],
                )
                self.assertEqual(r_body["verdict"], "FAIL")
                self.assertTrue(any(f["token"] == "Apache-Coyote/1.1" for f in r_body["findings"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 27/61: CFG-03 (Iteração SDD 097)", just2_txt)

    def test_iteration98_cfg04_guide_tooling(self) -> None:
        from casa_audit.scanner import evaluate_cfg04_csp

        def _ex(url: str, csp: str | None = None, ro_csp: str | None = None) -> dict:
            hdrs = {"content-type": "text/html; charset=utf-8"}
            if csp is not None:
                hdrs["content-security-policy"] = csp
            if ro_csp is not None:
                hdrs["content-security-policy-report-only"] = ro_csp
            return {"method": "GET", "url": url, "status": 200, "headers": hdrs, "body": "<html></html>"}

        with tempfile.TemporaryDirectory() as td_cfg4:
            tdp = Path(td_cfg4)
            # 1. Strict CSP (style-src 'unsafe-inline' is allowed when script-src is strict) -> PASS via Google csp-evaluator
            r_pass = evaluate_cfg04_csp(
                "http://127.0.0.1:9999",
                crawled_exchanges=[
                    _ex("http://127.0.0.1:9999/", "default-src 'none'; script-src 'self' https://scripts.example.com; style-src 'self' 'unsafe-inline'"),
                    _ex("http://127.0.0.1:9999/login", "default-src 'self'"),
                ],
                csp_out_path=tdp / "csp_pass.json",
            )
            self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
            self.assertTrue(r_pass["cspEvaluator"]["executed"])
            self.assertTrue((tdp / "csp_pass.json").exists())

            # 2. Forbidden tokens + missing + Report-Only -> FAIL detected by Google csp-evaluator (types 300/301/302/303/304)
            r_fail = evaluate_cfg04_csp(
                "http://127.0.0.1:9999",
                crawled_exchanges=[
                    _ex("http://127.0.0.1:9999/inline", "default-src 'self'; script-src 'self' 'unsafe-inline'"),
                    _ex("http://127.0.0.1:9999/eval", "default-src 'self' 'unsafe-eval'"),
                    _ex("http://127.0.0.1:9999/data", "default-src 'self'; script-src 'self' data:"),
                    _ex("http://127.0.0.1:9999/wild", "default-src *; script-src *"),
                    _ex("http://127.0.0.1:9999/nocsp", csp=None, ro_csp="default-src 'self'"),
                    _ex("http://127.0.0.1:9999/noscript", "object-src 'none'"),
                ],
                csp_out_path=tdp / "csp_fail.json",
            )
            self.assertEqual(r_fail["verdict"], "FAIL")
            self.assertEqual(len(r_fail["findings"]), 6)
            all_types = {t for f in r_fail["findings"] for t in f.get("cspEvaluatorTypes", [])}
            self.assertTrue({300, 301, 302, 303, 304}.issubset(all_types), f"Expected csp-evaluator types 300..304, got {all_types}")

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 28/61: CFG-04 (Iteração SDD 098)", just2_txt)

    def test_iteration99_cfg05_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg05_clickjacking

        class _Cfg05Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "xfo"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                m = type(self).mode
                p = self.path.split("?", 1)[0]
                self.send_response(200 if p == "/" else 404)
                self.send_header("Content-Type", "text/html")
                if m == "xfo":
                    self.send_header("X-Frame-Options", "SAMEORIGIN")
                elif m == "fa":
                    self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
                elif m == "wildcard":
                    self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors *")
                self.end_headers()
                self.wfile.write(b"<html><body>Page</body></html>")

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg05Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg5:
            tdp = Path(td_cfg5)
            try:
                # 1. X-Frame-Options: SAMEORIGIN -> PASS via OWASP ZAP 2.17.0
                _Cfg05Handler.mode = "xfo"
                r_xfo = evaluate_cfg05_clickjacking(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c5_xfo.json",
                    sarif_out_path=tdp / "zap_c5_xfo.sarif",
                )
                self.assertEqual(r_xfo["verdict"], "PASS", f"Expected PASS, got {r_xfo}")
                self.assertTrue(r_xfo["zap"]["executed"])

                # 2. Missing XFO and CSP frame-ancestors -> FAIL caught by real OWASP ZAP 10020
                _Cfg05Handler.mode = "vuln"
                r_vuln = evaluate_cfg05_clickjacking(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c5_vuln.json",
                    sarif_out_path=tdp / "zap_c5_vuln.sarif",
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                self.assertIn("10020", r_vuln["zapPluginsMatched"], f"Expected ZAP rule 10020, got {r_vuln}")

                # 3. CSP frame-ancestors 'none' -> PASS; frame-ancestors * -> FAIL
                _Cfg05Handler.mode = "fa"
                r_fa = evaluate_cfg05_clickjacking(f"http://127.0.0.1:{port}", zap_report=r_xfo["zap"])
                self.assertEqual(r_fa["verdict"], "PASS")

                _Cfg05Handler.mode = "wildcard"
                r_wild = evaluate_cfg05_clickjacking(f"http://127.0.0.1:{port}", zap_report=r_xfo["zap"])
                self.assertEqual(r_wild["verdict"], "FAIL")
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 29/61: CFG-05 (Iteração SDD 099)", just2_txt)

    def test_iteration100_cfg06_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg06_xcto

        class _Cfg06Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "clean"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                m = type(self).mode
                p = self.path.split("?", 1)[0]
                self.send_response(200)
                if p == "/metrics":
                    self.send_header("Content-Type", "text/html")
                    if m == "clean":
                        self.send_header("X-Content-Type-Options", "nosniff")
                elif m == "invalid" and p == "/":
                    self.send_header("Content-Type", "text/html")
                    self.send_header("X-Content-Type-Options", "invalid")
                else:
                    self.send_header("Content-Type", "text/html")
                    self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(b"<html><body><a href='/metrics'>metrics</a></body></html>")

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg06Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg6:
            tdp = Path(td_cfg6)
            try:
                # 1. 100% X-Content-Type-Options: nosniff -> PASS via OWASP ZAP 2.17.0
                _Cfg06Handler.mode = "clean"
                r_pass = evaluate_cfg06_xcto(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c6_pass.json",
                    sarif_out_path=tdp / "zap_c6_pass.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertEqual(r_pass["compliancePct"], 100.0)
                self.assertTrue(r_pass["zap"]["executed"])

                # 2. Missing X-Content-Type-Options on /metrics -> FAIL caught by real OWASP ZAP 10021
                _Cfg06Handler.mode = "partial"
                r_partial = evaluate_cfg06_xcto(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c6_partial.json",
                    sarif_out_path=tdp / "zap_c6_partial.sarif",
                )
                self.assertEqual(r_partial["verdict"], "FAIL")
                self.assertLess(r_partial["compliancePct"], 100.0)
                self.assertIn("10021", r_partial["zapPluginsMatched"], f"Expected ZAP rule 10021, got {r_partial}")

                # 3. Malformed X-Content-Type-Options -> FAIL
                _Cfg06Handler.mode = "invalid"
                r_invalid = evaluate_cfg06_xcto(f"http://127.0.0.1:{port}", zap_report=r_pass["zap"])
                self.assertEqual(r_invalid["verdict"], "FAIL")
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 30/61: CFG-06 (Iteração SDD 100)", just2_txt)

    def test_iteration101_cfg07_guide_tooling(self) -> None:
        import ssl
        import subprocess
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg07_anti_caching

        class _Cfg07Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "strict"

            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                p = self.path.split("?", 1)[0]
                if p == "/api/Users/":
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"data":{"id":7}}')
                    return
                if p == "/rest/user/login":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"authentication":{"token":"cfg07-jwt","bid":3}}')
                    return
                self.send_response(404)
                self.end_headers()

            def do_GET(self):
                m = type(self).mode
                p = self.path.split("?", 1)[0]
                if p in {"/rest/user/whoami", "/rest/basket/3", "/support/logs"}:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html" if p == "/support/logs" else "application/json")
                    if m == "strict":
                        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                    elif m == "private_only":
                        self.send_header("Cache-Control", "private, max-age=0")
                    self.end_headers()
                    self.wfile.write(b"<html><body>sensitive</body></html>" if p == "/support/logs" else b'{"ok":true}')
                    return
                self.send_response(404)
                self.end_headers()

        with tempfile.TemporaryDirectory() as td_cfg7:
            tdp = Path(td_cfg7)
            cert_path = tdp / "cert.pem"
            key_path = tdp / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key_path), "-out", str(cert_path),
                    "-days", "1", "-subj", "/CN=127.0.0.1",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg07Handler)
            srv.daemon_threads = True
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(str(cert_path), str(key_path))
            srv.socket = ssl_ctx.wrap_socket(srv.socket, server_side=True)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                # 1. Strict Cache-Control: no-store -> PASS via OWASP ZAP 2.17.0
                _Cfg07Handler.mode = "strict"
                r_pass = evaluate_cfg07_anti_caching(
                    f"https://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c7_pass.json",
                    sarif_out_path=tdp / "zap_c7_pass.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["authenticated"])
                self.assertTrue(r_pass["zap"]["executed"])

                # 2. Missing Cache-Control -> FAIL caught by real OWASP ZAP 10015 + authenticated probe
                _Cfg07Handler.mode = "missing"
                r_miss = evaluate_cfg07_anti_caching(
                    f"https://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c7_miss.json",
                    sarif_out_path=tdp / "zap_c7_miss.sarif",
                )
                self.assertEqual(r_miss["verdict"], "FAIL")
                self.assertTrue({"10049", "10015"} & set(r_miss["zapPluginsMatched"]), f"Expected ZAP 10015/10049, got {r_miss}")

                # 3. Cache-Control: private (without no-store) -> FAIL
                _Cfg07Handler.mode = "private_only"
                r_priv = evaluate_cfg07_anti_caching(f"https://127.0.0.1:{port}", zap_report=r_pass["zap"])
                self.assertEqual(r_priv["verdict"], "FAIL")
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 31/61: CFG-07 (Iteração SDD 101)", just2_txt)

    def test_iteration102_cfg08_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg08_cors

        class _Cfg08Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "strict"

            def log_message(self, fmt, *args):
                pass

            def _reply(self, status: int = 200):
                m = type(self).mode
                origin = self.headers.get("Origin", "")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if m == "strict":
                    if origin == "https://trusted.example.com":
                        self.send_header("Access-Control-Allow-Origin", origin)
                elif m == "wildcard_sensitive":
                    self.send_header("Access-Control-Allow-Origin", "*")
                elif m == "reflect_all":
                    if origin:
                        self.send_header("Access-Control-Allow-Origin", origin)
                        self.send_header("Access-Control-Allow-Credentials", "true")
                elif m == "wildcard_creds":
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Access-Control-Allow-Credentials", "true")
                self.end_headers()
                if status == 200:
                    self.wfile.write(b'{"status":"ok"}')

            def do_GET(self):
                self._reply(200)

            def do_OPTIONS(self):
                self._reply(204)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg08Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg8:
            tdp = Path(td_cfg8)
            try:
                # 1. Strict allowlist -> PASS via OWASP ZAP 2.17.0
                _Cfg08Handler.mode = "strict"
                r_pass = evaluate_cfg08_cors(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c8_pass.json",
                    sarif_out_path=tdp / "zap_c8_pass.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["zap"]["executed"])

                # 2. Permissive ACAO: * on sensitive routes -> FAIL caught by real OWASP ZAP 10098 + probe
                _Cfg08Handler.mode = "wildcard_sensitive"
                r_wild = evaluate_cfg08_cors(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c8_wild.json",
                    sarif_out_path=tdp / "zap_c8_wild.sarif",
                )
                self.assertEqual(r_wild["verdict"], "FAIL")
                self.assertIn("10098", r_wild["zapPluginsMatched"], f"Expected ZAP 10098, got {r_wild}")

                # 3. Reflection of foreign, null, and suffix-sharing origins -> FAIL
                _Cfg08Handler.mode = "reflect_all"
                r_refl = evaluate_cfg08_cors(f"http://127.0.0.1:{port}", zap_report=r_pass["zap"])
                self.assertEqual(r_refl["verdict"], "FAIL")
                vtypes = {f["violationType"] for f in r_refl["findings"]}
                self.assertTrue({"null_origin_accepted", "reflected_foreign_origin", "reflected_suffix_sharing_origin"}.issubset(vtypes))

                # 4. Wildcard + Access-Control-Allow-Credentials: true -> FAIL
                _Cfg08Handler.mode = "wildcard_creds"
                r_wc = evaluate_cfg08_cors(f"http://127.0.0.1:{port}", zap_report=r_pass["zap"])
                self.assertEqual(r_wc["verdict"], "FAIL")
                self.assertTrue(any(f["violationType"] == "wildcard_with_credentials" for f in r_wc["findings"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 32/61: CFG-08 (Iteração SDD 102)", just2_txt)

    def test_iteration103_cfg09_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg09_error_disclosure

        class _Cfg09Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "generic"

            def log_message(self, fmt, *args):
                pass

            def _read_body(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    return self.rfile.read(length)
                return b""

            def do_GET(self):
                m = type(self).mode
                p = self.path.split("?", 1)[0]
                if p == "/":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    if m == "sql_trace":
                        self.wfile.write(b'<html><body><a href="/rest/products/search?q=%27))">search</a></body></html>')
                    else:
                        self.wfile.write(b"<html><body>Home</body></html>")
                    return
                if m == "generic":
                    self.send_response(404 if "nonexistent" in p else 400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"Invalid request"}')
                    return
                if m == "sql_trace" and "/rest/products/search" in p:
                    self.send_response(500)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body>You have an error in your SQL syntax; SQLITE_ERROR\n"
                        b"Traceback (most recent call last):\n"
                        b'<ul id="stacktrace"><li>at Object.search (node_modules/sequelize/lib/model.js:12:4)</li></ul>'
                        b"</body></html>"
                    )
                    return
                if m == "path_leak" and "nonexistent" in p:
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"ENOENT: no such file '/srv/app/config/secret.md'")
                    return
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"Invalid request"}')

            def do_POST(self):
                body = self._read_body()
                if type(self).mode == "generic":
                    self.send_response(413 if len(body) > 100000 else 400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"Request rejected"}')
                    return
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"Request rejected"}')

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg09Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg9:
            tdp = Path(td_cfg9)
            try:
                # 1. Generic 4xx error messages -> PASS via OWASP ZAP 2.17.0
                _Cfg09Handler.mode = "generic"
                r_pass = evaluate_cfg09_error_disclosure(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c9_pass.json",
                    sarif_out_path=tdp / "zap_c9_pass.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertGreaterEqual(r_pass["inspected4xx5xxCount"], 1)
                self.assertTrue(r_pass["zap"]["executed"])

                # 2. HTTP 500 SQL syntax + Traceback -> FAIL caught by real OWASP ZAP 90022 + probe
                _Cfg09Handler.mode = "sql_trace"
                r_sql = evaluate_cfg09_error_disclosure(
                    f"http://127.0.0.1:{port}",
                    json_out_path=tdp / "zap_c9_sql.json",
                    sarif_out_path=tdp / "zap_c9_sql.sarif",
                )
                self.assertEqual(r_sql["verdict"], "FAIL")
                self.assertIn("90022", r_sql["zapPluginsMatched"], f"Expected ZAP 90022, got {r_sql}")

                # 3. 404 ENOENT filesystem path leak -> FAIL
                _Cfg09Handler.mode = "path_leak"
                r_path = evaluate_cfg09_error_disclosure(f"http://127.0.0.1:{port}", zap_report=r_pass["zap"])
                self.assertEqual(r_path["verdict"], "FAIL")
                self.assertTrue(any("filesystem_path" in f["classes"] for f in r_path["findings"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 33/61: CFG-09 (Iteração SDD 103)", just2_txt)

    def test_iteration104_cfg10_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg10_admin_reachability

        class _Cfg10Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "protected"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                m = type(self).mode
                p = self.path.split("?", 1)[0]
                is_auth = self.headers.get("Authorization") == "Bearer admin-jwt"

                if p in {"/admin", "/support/logs", "/rest/admin/application-configuration"}:
                    if m == "admin_exposed" or is_auth:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"admin":"panel","logs":["audit-1","audit-2"]}')
                        return
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"Unauthorized"}')
                    return

                if p == "/rest/wallet/balance":
                    if m == "wallet_bypass" or is_auth:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"balance":999.5}')
                        return
                    self.send_response(401)
                    self.end_headers()
                    return

                if p in {"/rest/basket/1", "/api/Users/1", "/api/Cards", "/rest/2fa/status", "/rest/user/whoami"}:
                    if is_auth:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"data":"ok"}')
                        return
                    self.send_response(401)
                    self.end_headers()
                    return

                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg10Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg10:
            tdp = Path(td_cfg10)
            auth_h = {"Authorization": "Bearer admin-jwt"}
            try:
                # 1. Protected admin & authenticated endpoints -> PASS via OWASP ZAP 2.17.0 + SecLists
                _Cfg10Handler.mode = "protected"
                r_pass = evaluate_cfg10_admin_reachability(
                    f"http://127.0.0.1:{port}",
                    auth_headers=auth_h,
                    json_out_path=tdp / "zap_c10_pass.json",
                    sarif_out_path=tdp / "zap_c10_pass.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertGreaterEqual(r_pass["wordlistCount"], 20)
                self.assertTrue(r_pass["zap"]["executed"])

                # 2. Admin paths exposed unauthenticated with LCS >= 0.90 -> FAIL (ZAP discovery + SecLists)
                _Cfg10Handler.mode = "admin_exposed"
                r_adm = evaluate_cfg10_admin_reachability(
                    f"http://127.0.0.1:{port}",
                    auth_headers=auth_h,
                    json_out_path=tdp / "zap_c10_adm.json",
                    sarif_out_path=tdp / "zap_c10_adm.sarif",
                )
                self.assertEqual(r_adm["verdict"], "FAIL")
                self.assertTrue(any(f["kind"] == "exposed_admin_wordlist_path" and f["similarity"] >= 0.90 for f in r_adm["findings"]))
                self.assertGreaterEqual(len(r_adm["zapDiscoveredAdminUrls"]), 1)

                # 3. Authenticated route (/rest/wallet/balance) bypass -> FAIL
                _Cfg10Handler.mode = "wallet_bypass"
                r_wal = evaluate_cfg10_admin_reachability(
                    f"http://127.0.0.1:{port}",
                    auth_headers=auth_h,
                    zap_report=r_pass["zap"],
                )
                self.assertEqual(r_wal["verdict"], "FAIL")
                self.assertTrue(any(f["kind"] == "authenticated_route_bypass" for f in r_wal["findings"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 34/61: CFG-10 (Iteração SDD 104)", just2_txt)

    def test_iteration105_cfg11_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_cfg11_dns_takeover

        class _Cfg11Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "clean"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                if type(self).mode == "github_takeover":
                    self.send_response(404)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>404</h1><p>There isn't a GitHub Pages site here.</p></body></html>")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>Healthy Origin</body></html>")

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Cfg11Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_cfg11:
            tdp = Path(td_cfg11)
            try:
                # 1. Clean localhost resolution via real dnsx 1.3.1 + Nuclei 3.11.1 -> PASS
                _Cfg11Handler.mode = "clean"
                r_pass = evaluate_cfg11_dns_takeover(
                    f"http://localhost:{port}",
                    root_body="<html><body>Healthy Origin</body></html>",
                    dnsx_out_path=tdp / "dnsx_pass.json",
                    nuclei_jsonl_path=tdp / "nuc_c11_pass.jsonl",
                    nuclei_sarif_path=tdp / "nuc_c11_pass.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["dnsx"]["executed"])
                self.assertTrue(r_pass["nuclei"]["executed"])
                self.assertTrue((tdp / "dnsx_pass.json").exists())

                # 2. Dangling CNAME chain pointing to unclaimed Herokuapp with NXDOMAIN -> FAIL
                r_nx = evaluate_cfg11_dns_takeover(
                    f"http://127.0.0.1:{port}",
                    cname_lookup_fn=lambda h: ([h, "orphan-app.herokuapp.com"], "NXDOMAIN", []),
                    dnsx_out_path=tdp / "dnsx_nx.json",
                    nuclei_jsonl_path=tdp / "nuc_c11_nx.jsonl",
                    nuclei_sarif_path=tdp / "nuc_c11_nx.sarif",
                )
                self.assertEqual(r_nx["verdict"], "FAIL")
                self.assertTrue(any(f["reason"] == "dangling_cname_nxdomain" for f in r_nx["findings"]))

                # 3. Real Nuclei v3.11.1 takeover banner match ("There isn't a GitHub Pages site here.") -> FAIL
                _Cfg11Handler.mode = "github_takeover"
                r_gh = evaluate_cfg11_dns_takeover(
                    f"http://127.0.0.1:{port}",
                    cname_lookup_fn=lambda h: ([h, "unclaimed-docs.github.io"], "NOERROR", ["185.199.108.153"]),
                    dnsx_out_path=tdp / "dnsx_gh.json",
                    nuclei_jsonl_path=tdp / "nuc_c11_gh.jsonl",
                    nuclei_sarif_path=tdp / "nuc_c11_gh.sarif",
                )
                self.assertEqual(r_gh["verdict"], "FAIL")
                self.assertIn("casa3-cfg11-subdomain-takeover", r_gh["nucleiTemplatesMatched"])
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 35/61: CFG-11 (Iteração SDD 105)", just2_txt)

    def test_iteration106_aut01_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_aut01_default_credentials

        class _Aut01Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "reject"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>Login Portal</body></html>")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8") if length else "{}"
                data = json.loads(raw) if raw else {}
                p = self.path.split("?", 1)[0]
                if p == "/rest/user/login":
                    u = data.get("email") or data.get("username") or ""
                    pw = data.get("password") or ""
                    m = type(self).mode
                    if m == "generic_demo" and u == "demo" and pw == "demo":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Set-Cookie", "sid=supersecret-cookie")
                        self.end_headers()
                        self.wfile.write(b'{"authentication":{"token":"eyJ-generic-demo"}}')
                        return
                    if m == "vendor_tomcat" and u == "tomcat" and pw == "tomcat":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"token":"eyJ-vendor-tomcat"}')
                        return
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"Invalid email or password."}')
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Aut01Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_aut1:
            tdp = Path(td_aut1)
            try:
                # 1. All SecLists credentials rejected -> PASS + redacted HAR written
                _Aut01Handler.mode = "reject"
                r_pass = evaluate_aut01_default_credentials(
                    f"http://127.0.0.1:{port}",
                    har_out_path=tdp / "aut01_pass.har",
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertGreaterEqual(r_pass["corpusCount"], 10)
                self.assertTrue((tdp / "aut01_pass.har").exists())

                # 2. SecLists generic default demo:demo accepted -> FAIL + redacted Set-Cookie/password in HAR
                _Aut01Handler.mode = "generic_demo"
                har_demo = tdp / "aut01_demo.har"
                r_demo = evaluate_aut01_default_credentials(
                    f"http://127.0.0.1:{port}",
                    har_out_path=har_demo,
                )
                self.assertEqual(r_demo["verdict"], "FAIL")
                self.assertTrue(any(f["account"] == "demo" and f["kind"] == "generic_default_credential" for f in r_demo["findings"]))
                har_txt = har_demo.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("supersecret-cookie", har_txt)

                # 3. Vendor default tomcat:tomcat triggered dynamically from CFG-03 version disclosure -> FAIL
                _Aut01Handler.mode = "vendor_tomcat"
                r_tom = evaluate_aut01_default_credentials(
                    f"http://127.0.0.1:{port}",
                    cfg03_findings=[{"token": "Apache-Coyote/1.1", "detail": "Tomcat header disclosure"}],
                    har_out_path=tdp / "aut01_tomcat.har",
                )
                self.assertEqual(r_tom["verdict"], "FAIL")
                self.assertTrue(any(f["account"] == "tomcat" and f["kind"] == "product_vendor_default" for f in r_tom["findings"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 36/61: AUT-01 (Iteração SDD 106)", just2_txt)


if __name__ == "__main__":
    unittest.main()

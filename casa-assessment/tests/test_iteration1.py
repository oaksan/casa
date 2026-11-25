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
                body = b'{"status":"ok"}' if status == 200 else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
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
                if body:
                    self.wfile.write(body)

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
                    body = (
                        b'<html><body><a href="/rest/products/search?q=%27))">search</a></body></html>'
                        if m == "sql_trace"
                        else b"<html><body>Home</body></html>"
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if m == "generic":
                    body = b'{"error":"Invalid request"}'
                    self.send_response(404 if "nonexistent" in p else 400)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if m == "sql_trace" and "/rest/products/search" in p:
                    body = (
                        b"<html><body>You have an error in your SQL syntax; SQLITE_ERROR\n"
                        b"Traceback (most recent call last):\n"
                        b'<ul id="stacktrace"><li>at Object.search (node_modules/sequelize/lib/model.js:12:4)</li></ul>'
                        b"</body></html>"
                    )
                    self.send_response(500)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if m == "path_leak" and "nonexistent" in p:
                    body = b"ENOENT: no such file '/srv/app/config/secret.md'"
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = b'{"error":"Invalid request"}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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

    def test_iteration107_aut02_guide_tooling(self) -> None:
        import secrets
        import time
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_aut02_token_entropy

        class _Aut02Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "csprng128"

            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                p = self.path.split("?", 1)[0]
                if p == "/rest/user/login":
                    m = type(self).mode
                    if m == "csprng128":
                        tok = secrets.token_hex(16)
                    elif m == "weak32":
                        tok = secrets.token_hex(4)
                    else:
                        tok = f"deterministic-iat-{int(time.time() * 2) % 4}"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", f"sid={tok}; HttpOnly")
                    self.end_headers()
                    self.wfile.write(json.dumps({"token": tok}).encode("utf-8"))
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Aut02Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_aut2:
            tdp = Path(td_aut2)
            try:
                # 1. 200 distinct 128-bit CSPRNG tokens -> PASS (>= 64.0 bits SP 800-90B MCV) + redacted HAR
                _Aut02Handler.mode = "csprng128"
                har_pass = tdp / "aut02_pass.har"
                rep_pass = tdp / "aut02_pass.json"
                r_pass = evaluate_aut02_token_entropy(
                    f"http://127.0.0.1:{port}",
                    credentials=("user@example.com", "pw"),
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertEqual(r_pass["samplesCollected"], 200)
                self.assertEqual(r_pass["distinctTokens"], 200)
                self.assertGreaterEqual(r_pass["minEntropyBits"], 64.0)
                self.assertIn("[REDACTED]", har_pass.read_text(encoding="utf-8"))
                self.assertTrue(rep_pass.exists())

                # 2. Colliding deterministic tokens -> FAIL
                _Aut02Handler.mode = "colliding"
                r_dup = evaluate_aut02_token_entropy(
                    f"http://127.0.0.1:{port}",
                    credentials=("user@example.com", "pw"),
                    report_out_path=tdp / "aut02_dup.json",
                    har_out_path=tdp / "aut02_dup.har",
                )
                self.assertEqual(r_dup["verdict"], "FAIL")
                self.assertGreater(r_dup["duplicateTokens"], 0)
                self.assertLess(r_dup["minEntropyBits"], 64.0)

                # 3. 200 distinct 32-bit weak hex tokens -> FAIL (< 64 bits SP 800-90B)
                _Aut02Handler.mode = "weak32"
                r_weak = evaluate_aut02_token_entropy(
                    f"http://127.0.0.1:{port}",
                    credentials=("user@example.com", "pw"),
                    report_out_path=tdp / "aut02_weak.json",
                    har_out_path=tdp / "aut02_weak.har",
                )
                self.assertEqual(r_weak["verdict"], "FAIL")
                self.assertLess(r_weak["minEntropyBits"], 64.0)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 37/61: AUT-02 (Iteração SDD 107)", just2_txt)

    def test_iteration108_aut03_guide_tooling(self) -> None:
        import secrets
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_aut03_session_fixation

        class _Aut03Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "rotated"
            valid_sessions: set[str] = set()
            pre_session = "preauth_sid_0001"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                if p == "/" or p == "/rest/user/whoami":
                    body = b"<html><body>Anonymous</body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Set-Cookie", f"sid={type(self).pre_session}; Path=/; HttpOnly")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p == "/rest/wallet/balance":
                    cookie_hdr = self.headers.get("Cookie", "")
                    auth_hdr = self.headers.get("Authorization", "")
                    presented = set()
                    for part in cookie_hdr.split(";"):
                        if "=" in part:
                            presented.add(part.split("=", 1)[1].strip())
                    if auth_hdr.startswith("Bearer "):
                        presented.add(auth_hdr.split(" ", 1)[1].strip())
                    ok = bool(presented & type(self).valid_sessions)
                    if ok:
                        body = b'{"status":"success","data":{"balance":100}}'
                        self.send_response(200)
                    else:
                        body = b'{"error":"Unauthorized"}'
                        self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                p = self.path.split("?", 1)[0]
                if p == "/rest/user/login":
                    m = type(self).mode
                    if m == "rotated":
                        new_tok = "rot_" + secrets.token_hex(16)
                        type(self).valid_sessions = {new_tok}
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Set-Cookie", f"sid={new_tok}; Path=/; HttpOnly")
                        self.end_headers()
                        self.wfile.write(json.dumps({"token": new_tok}).encode("utf-8"))
                        return
                    if m == "fixated":
                        # Vulnerable: keeps pre-auth / injected sid valid without rotating
                        type(self).valid_sessions = {type(self).pre_session, "casa3_preauth_fixation_probe_deadbeef"}
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Set-Cookie", f"sid={type(self).pre_session}; Path=/; HttpOnly")
                        self.end_headers()
                        self.wfile.write(json.dumps({"token": type(self).pre_session}).encode("utf-8"))
                        return
                    if m == "pre_still_valid":
                        # Vulnerable: issues a new token on login, but leaves pre_session authenticated server-side
                        new_tok = "rot_" + secrets.token_hex(16)
                        type(self).valid_sessions = {type(self).pre_session, new_tok}
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Set-Cookie", f"sid={new_tok}; Path=/; HttpOnly")
                        self.end_headers()
                        self.wfile.write(json.dumps({"token": new_tok}).encode("utf-8"))
                        return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Aut03Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_aut3:
            tdp = Path(td_aut3)
            try:
                # 1. Rotated token + pre-auth session rejected -> PASS + redacted HAR
                _Aut03Handler.mode = "rotated"
                _Aut03Handler.valid_sessions = set()
                har_pass = tdp / "aut03_pass.har"
                r_pass = evaluate_aut03_session_fixation(
                    f"http://127.0.0.1:{port}",
                    credentials=("user@example.com", "SuperSecret!1"),
                    protected_endpoints=["/rest/wallet/balance"],
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["postToken"].startswith("rot_"))
                self.assertGreaterEqual(len(r_pass["preSessionCookies"]), 1)
                self.assertGreaterEqual(r_pass["replayedChecks"], 2)
                har_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("SuperSecret!1", har_txt)

                # 2. Session fixation (same identifier kept on login) -> FAIL
                _Aut03Handler.mode = "fixated"
                _Aut03Handler.valid_sessions = set()
                r_fix = evaluate_aut03_session_fixation(
                    f"http://127.0.0.1:{port}",
                    credentials=("user@example.com", "SuperSecret!1"),
                    protected_endpoints=["/rest/wallet/balance"],
                    har_out_path=tdp / "aut03_fix.har",
                )
                self.assertEqual(r_fix["verdict"], "FAIL")
                self.assertTrue(any(s["ruleId"] == "CASA3-AUT-03" for s in r_fix["sarifResults"]))

                # 3. New token issued, but pre-auth identifier still accepted after login -> FAIL
                _Aut03Handler.mode = "pre_still_valid"
                _Aut03Handler.valid_sessions = set()
                r_stale = evaluate_aut03_session_fixation(
                    f"http://127.0.0.1:{port}",
                    credentials=("user@example.com", "SuperSecret!1"),
                    protected_endpoints=["/rest/wallet/balance"],
                    har_out_path=tdp / "aut03_stale.har",
                )
                self.assertEqual(r_stale["verdict"], "FAIL")
                self.assertTrue(any("CWE-384" in f for f in r_stale["findings"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 38/61: AUT-03 (Iteração SDD 108)", just2_txt)

    def test_iteration109_aut04_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_aut04_url_token_leak

        class _Aut04Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "clean"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                if p == "/":
                    body = b"<html><body>Home</body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p == "/rest/user/change-password" and m == "get_creds":
                    body = b'{"user":{"id":1,"email":"probe@example.com"}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = b'{"error":"Method not allowed"}'
                self.send_response(405 if p == "/rest/user/change-password" else 404)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                p = self.path.split("?", 1)[0]
                if p == "/api/Users/":
                    body = b'{"status":"success","data":{"id":99}}'
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p == "/rest/user/login":
                    body = json.dumps({"authentication": {"token": "hdr_only_session_token_987654321"}}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Aut04Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_aut4:
            tdp = Path(td_aut4)
            try:
                # 1. Clean crawl + POST-only change-password + real OWASP ZAP -> PASS
                _Aut04Handler.mode = "clean"
                har_clean = tdp / "aut04_clean.har"
                r_pass = evaluate_aut04_url_token_leak(
                    f"http://127.0.0.1:{port}",
                    observed_tokens={"hdr_only_session_token_987654321"},
                    crawled_exchanges=[
                        {
                            "method": "GET",
                            "url": f"http://127.0.0.1:{port}/rest/products/search?q=apple",
                            "status": 200,
                            "headers": {"content-type": "application/json"},
                            "request_headers": {"referer": f"http://127.0.0.1:{port}/"},
                            "body": "{}",
                        }
                    ],
                    json_out_path=tdp / "zap_a4.json",
                    sarif_out_path=tdp / "zap_a4.sarif",
                    har_out_path=har_clean,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["zap"]["executed"])
                self.assertTrue(har_clean.exists())

                # 2. Active token in outbound request Referer & redirect Location -> FAIL
                r_ref = evaluate_aut04_url_token_leak(
                    f"http://127.0.0.1:{port}",
                    observed_tokens={"active_bearer_token_1234567890"},
                    crawled_exchanges=[
                        {
                            "method": "GET",
                            "url": f"http://127.0.0.1:{port}/external/analytics",
                            "status": 302,
                            "headers": {"location": f"https://thirdparty.example/cb?token=active_bearer_token_1234567890"},
                            "request_headers": {"referer": f"http://127.0.0.1:{port}/auth?code=1&token=active_bearer_token_1234567890"},
                            "body": "",
                        }
                    ],
                    zap_report=r_pass["zap"],
                    har_out_path=tdp / "aut04_ref.har",
                )
                self.assertEqual(r_ref["verdict"], "FAIL")
                channels_ref = {f["channel"] for f in r_ref["findings"]}
                self.assertIn("Referer_Header_Leak", channels_ref)
                self.assertIn("Redirect_Location_Token_Leak", channels_ref)
                self.assertIn("[REDACTED]", (tdp / "aut04_ref.har").read_text(encoding="utf-8"))

                # 3. CWE-598 GET query string credential acceptance + URL query redaction -> FAIL
                _Aut04Handler.mode = "get_creds"
                har_get = tdp / "aut04_get.har"
                r_get = evaluate_aut04_url_token_leak(
                    f"http://127.0.0.1:{port}",
                    zap_report=r_pass["zap"],
                    har_out_path=har_get,
                )
                self.assertEqual(r_get["verdict"], "FAIL")
                self.assertTrue(any(f["channel"] == "CWE-598_GET_Credential_Query" for f in r_get["findings"]))
                self.assertTrue(any(s["ruleId"] == "CASA3-AUT-04" for s in r_get["sarifResults"]))
                har_get_txt = har_get.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_get_txt)
                self.assertNotIn("Casa3Aut04Old!99", har_get_txt)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 39/61: AUT-04 (Iteração SDD 109)", just2_txt)

    def test_iteration110_aut05_guide_tooling(self) -> None:
        import secrets
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_aut05_logout_invalidation

        class _Aut05Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "revokes_both"
            active_sessions: set[str] = set()
            active_refresh: set[str] = set()

            def log_message(self, fmt, *args):
                pass

            def _read_body(self):
                length = int(self.headers.get("Content-Length", "0"))
                return self.rfile.read(length) if length else b""

            def _extract_presented_tokens(self):
                tokens = set()
                cookie_hdr = self.headers.get("Cookie", "")
                for part in cookie_hdr.split(";"):
                    if "=" in part:
                        tokens.add(part.split("=", 1)[1].strip())
                auth_hdr = self.headers.get("Authorization", "")
                if auth_hdr.startswith("Bearer "):
                    tokens.add(auth_hdr.split(" ", 1)[1].strip())
                return tokens

            def do_GET(self):
                p = self.path.split("?", 1)[0]
                if p == "/rest/wallet/balance":
                    ok = bool(self._extract_presented_tokens() & type(self).active_sessions)
                    body = b'{"status":"success","data":{"balance":100}}' if ok else b'{"error":"Unauthorized"}'
                    self.send_response(200 if ok else 401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p == "/rest/user/whoami":
                    ok = bool(self._extract_presented_tokens() & type(self).active_sessions)
                    body = b'{"user":{"email":"u@example.com"}}' if ok else b'{"user":{}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p in {"/rest/user/logout", "/logout", "/rest/saveLoginIp"}:
                    self.send_response(405)
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                raw = self._read_body()
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                if p == "/rest/user/login":
                    sess = "sess_" + secrets.token_hex(12)
                    ref = "ref_" + secrets.token_hex(12)
                    type(self).active_sessions = {sess}
                    type(self).active_refresh = {ref}
                    body = json.dumps({"token": sess, "refresh_token": ref}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", f"sid={sess}; Path=/; HttpOnly")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p == "/api/logout":
                    if m == "revokes_both":
                        type(self).active_sessions.clear()
                        type(self).active_refresh.clear()
                    elif m == "refresh_survives":
                        type(self).active_sessions.clear()
                    # session_survives leaves both active
                    body = b'{"loggedOut":true}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p == "/rest/user/refresh":
                    try:
                        req_j = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
                    except Exception:
                        req_j = {}
                    presented_ref = req_j.get("refresh_token", "")
                    if presented_ref and presented_ref in type(self).active_refresh:
                        body = json.dumps({"token": "new_" + secrets.token_hex(12)}).encode("utf-8")
                        self.send_response(200)
                    else:
                        body = b'{"error":"Refresh token revoked"}'
                        self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Aut05Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_aut5:
            tdp = Path(td_aut5)
            try:
                # 1. Server revokes BOTH session & refresh token on logout -> PASS + redacted HAR
                _Aut05Handler.mode = "revokes_both"
                har_pass = tdp / "aut05_pass.har"
                r_pass = evaluate_aut05_logout_invalidation(
                    f"http://127.0.0.1:{port}",
                    credentials=("u@example.com", "LogoutSecret!1"),
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["serverLogoutFound"])
                har_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("LogoutSecret!1", har_txt)

                # 2. Session token/cookie still accepted after logout -> FAIL
                _Aut05Handler.mode = "session_survives"
                r_sess = evaluate_aut05_logout_invalidation(
                    f"http://127.0.0.1:{port}",
                    credentials=("u@example.com", "LogoutSecret!1"),
                    har_out_path=tdp / "aut05_sess.har",
                )
                self.assertEqual(r_sess["verdict"], "FAIL")
                self.assertTrue(any(f["channel"] == "post_logout_session_replay" for f in r_sess["findings"]))

                # 3. Session token revoked, yet refresh token STILL accepted after logout -> FAIL
                _Aut05Handler.mode = "refresh_survives"
                r_ref = evaluate_aut05_logout_invalidation(
                    f"http://127.0.0.1:{port}",
                    credentials=("u@example.com", "LogoutSecret!1"),
                    har_out_path=tdp / "aut05_ref.har",
                )
                self.assertEqual(r_ref["verdict"], "FAIL")
                self.assertTrue(any(f["channel"] == "post_logout_refresh_replay" for f in r_ref["findings"]))
                self.assertTrue(any(s["ruleId"] == "CASA3-AUT-05" for s in r_ref["sarifResults"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 40/61: AUT-05 (Iteração SDD 110)", just2_txt)

    def test_iteration111_aut06_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_aut06_session_cookie_flags

        class _Aut06Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "strict"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                if p == "/" or p == "/rest/user/whoami":
                    body = b'<html><body><a href="/rest/user/whoami">whoami</a></body></html>' if p == "/" else b'{"user":{"email":"u@example.com"}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8" if p == "/" else "application/json; charset=utf-8")
                    if m == "strict":
                        self.send_header("Set-Cookie", "sid=strict_tok_123456; Path=/; Secure; HttpOnly; SameSite=Strict")
                        self.send_header("Set-Cookie", "prefs=dark; Path=/")
                    elif m == "insecure_cookie":
                        self.send_header("Set-Cookie", "sessionid=weak_tok_123456; Path=/")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = b'{"error":"Not found"}'
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                if p == "/rest/user/login":
                    if m == "strict":
                        body = b'{"status":"ok"}'
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Set-Cookie", "sid=strict_tok_123456; Path=/; Secure; HttpOnly; SameSite=Strict")
                        self.send_header("Set-Cookie", "prefs=dark; Path=/")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    if m == "insecure_cookie":
                        body = b'{"status":"ok"}'
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Set-Cookie", "sessionid=weak_tok_123456; Path=/")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    body = b'{"authentication":{"token":"json_only_no_cookie_123456"}}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Aut06Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_aut6:
            tdp = Path(td_aut6)
            try:
                # 1. Strict Secure + HttpOnly + SameSite=Strict on session cookie (benign prefs cookie ignored) -> PASS + real OWASP ZAP
                _Aut06Handler.mode = "strict"
                har_pass = tdp / "aut06_pass.har"
                r_pass = evaluate_aut06_session_cookie_flags(
                    f"http://127.0.0.1:{port}",
                    credentials=("u@example.com", "CookieSecret!1"),
                    json_out_path=tdp / "zap_a6_pass.json",
                    sarif_out_path=tdp / "zap_a6_pass.sarif",
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["zap"]["executed"])
                har_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("CookieSecret!1", har_txt)

                # 2. Session cookie without Secure / HttpOnly / SameSite -> FAIL via real OWASP ZAP (10010/10054) + parser
                _Aut06Handler.mode = "insecure_cookie"
                r_weak = evaluate_aut06_session_cookie_flags(
                    f"http://127.0.0.1:{port}",
                    credentials=("u@example.com", "CookieSecret!1"),
                    json_out_path=tdp / "zap_a6_weak.json",
                    sarif_out_path=tdp / "zap_a6_weak.sarif",
                    har_out_path=tdp / "aut06_weak.har",
                )
                self.assertEqual(r_weak["verdict"], "FAIL")
                self.assertTrue(
                    bool({"10010", "10011", "10054"} & set(r_weak["zapPluginsMatched"])),
                    f"Expected ZAP 10010/10011/10054 in {r_weak}",
                )

                # 3. JSON token with zero server Set-Cookie headers -> FAIL
                _Aut06Handler.mode = "json_only"
                r_json = evaluate_aut06_session_cookie_flags(
                    f"http://127.0.0.1:{port}",
                    credentials=("u@example.com", "CookieSecret!1"),
                    zap_report=r_pass["zap"],
                    har_out_path=tdp / "aut06_json.har",
                )
                self.assertEqual(r_json["verdict"], "FAIL")
                self.assertTrue(any(s["ruleId"] == "CASA3-AUT-06" for s in r_json["sarifResults"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 41/61: AUT-06 (Iteração SDD 111)", just2_txt)

    def test_iteration112_aut07_guide_tooling(self) -> None:
        import base64
        import hashlib
        import hmac
        import time
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_aut07_jwt_security

        def _b64u(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        def _make_hs256(secret_bytes: bytes, iat_ts: int | None, exp_ts: int | None, alg: str = "HS256") -> str:
            hdr = _b64u(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
            pay_d: dict = {"sub": "user@example.com"}
            if iat_ts is not None:
                pay_d["iat"] = iat_ts
            if exp_ts is not None:
                pay_d["exp"] = exp_ts
            pay = _b64u(json.dumps(pay_d, separators=(",", ":")).encode("utf-8"))
            sig = _b64u(hmac.new(secret_bytes, f"{hdr}.{pay}".encode("utf-8"), hashlib.sha256).digest())
            return f"{hdr}.{pay}.{sig}"

        strong_secret = b"SuperStrong256BitPlusSecretKeyForCasa3Testing_2026!!"
        weak_secret = b"shortkey"
        fake_pubkey = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest\n-----END PUBLIC KEY-----\n"

        class _Aut07Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "strict"
            valid_tok = ""

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                if p == "/encryptionkeys/jwt.pub":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(fake_pubkey)))
                    self.end_headers()
                    self.wfile.write(fake_pubkey)
                    return
                if p == "/rest/wallet/balance":
                    auth = self.headers.get("Authorization", "")
                    tok = auth.split(" ", 1)[1].strip() if auth.startswith("Bearer ") else ""
                    accepted = False
                    if tok and tok.count(".") == 2:
                        h_s, p_s, s_s = tok.split(".")
                        try:
                            hdr = json.loads(base64.urlsafe_b64decode(h_s + "=" * (-len(h_s) % 4)))
                        except Exception:
                            hdr = {}
                        if m == "strict":
                            accepted = tok == type(self).valid_tok
                        elif m == "vulns":
                            if hdr.get("alg", "").lower() == "none":
                                accepted = True
                            elif hdr.get("alg") == "HS256":
                                expected_s = _b64u(hmac.new(fake_pubkey, f"{h_s}.{p_s}".encode("utf-8"), hashlib.sha256).digest())
                                if hmac.compare_digest(s_s, expected_s):
                                    accepted = True
                    body = b'{"data":{"balance":42}}' if accepted else b'{"error":"Invalid token"}'
                    self.send_response(200 if accepted else 401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Aut07Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        now = int(time.time())
        with tempfile.TemporaryDirectory() as td_aut7:
            tdp = Path(td_aut7)
            try:
                # 1. Strict HS256 with 3600s exp denying all 5 crafted vectors + redacted HAR + key length Not_Covered when no source -> PASS
                _Aut07Handler.mode = "strict"
                strict_tok = _make_hs256(strong_secret, now, now + 3600)
                _Aut07Handler.valid_tok = strict_tok
                har_pass = tdp / "aut07_pass.har"
                rep_pass = tdp / "aut07_pass.json"
                r_pass = evaluate_aut07_jwt_security(
                    f"http://127.0.0.1:{port}",
                    token=strict_tok,
                    post_logout_accepted=True,
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertEqual(r_pass["hmacKeyBits"], "Not_Covered")
                self.assertGreaterEqual(r_pass["vectorsTested"], 5)
                har_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn(strict_tok, har_txt)
                self.assertTrue(rep_pass.exists())

                # 2. Accepts alg:none & HS256 public-key confusion -> FAIL
                _Aut07Handler.mode = "vulns"
                r_vuln = evaluate_aut07_jwt_security(
                    f"http://127.0.0.1:{port}",
                    token=strict_tok,
                    post_logout_accepted=False,
                    report_out_path=tdp / "aut07_vuln.json",
                    har_out_path=tdp / "aut07_vuln.har",
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                vecs = {f["vector"] for f in r_vuln["findings"]}
                self.assertTrue({"unsigned_alg_none", "algorithm_confusion_hs256_pubkey"}.issubset(vecs))

                # 3. Non-revocable token with exp > 86400s + weak HS256 key (< 256 bits) from source -> FAIL
                _Aut07Handler.mode = "strict"
                long_tok = _make_hs256(weak_secret, now, now + 172800)
                _Aut07Handler.valid_tok = long_tok
                r_exp = evaluate_aut07_jwt_security(
                    f"http://127.0.0.1:{port}",
                    token=long_tok,
                    post_logout_accepted=True,
                    source_text='const jwtSecret = "shortkey";',
                    report_out_path=tdp / "aut07_exp.json",
                    har_out_path=tdp / "aut07_exp.har",
                )
                self.assertEqual(r_exp["verdict"], "FAIL")
                vecs_exp = {f["vector"] for f in r_exp["findings"]}
                self.assertIn("excessive_token_lifetime", vecs_exp)
                self.assertIn("weak_hs256_key", vecs_exp)
                self.assertTrue(any(s["ruleId"] == "CASA3-AUT-07" for s in r_exp["sarifResults"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 42/61: AUT-07 (Iteração SDD 112)", just2_txt)

    def test_iteration113_aut08_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_aut08_client_storage

        class _Aut08Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "clean_httponly"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                if p == "/" or p == "/index.html":
                    html_doc = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>AUT-08 Test</title></head>
<body>
  <input id="email" type="email" />
  <input id="password" type="password" />
  <button id="loginButton" type="button" onclick="doLogin()">Login</button>
  <button id="navbarLogoutButton" type="button" onclick="doLogout()">Logout</button>
  <script>
    const MODE = {json.dumps(m)};
    async function doLogin() {{
      const email = document.querySelector('#email').value;
      const password = document.querySelector('#password').value;
      const r = await fetch('/rest/user/login', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ email, password }})
      }});
      const data = await r.json();
      if (MODE === 'leaky_before_logout') {{
        localStorage.setItem('token', data.token);
        sessionStorage.setItem('profileEmail', email);
      }} else if (MODE === 'survives_logout') {{
        sessionStorage.setItem('session_marker', 'secret_surviving_token_value');
      }}
      document.documentElement.dataset.aut08Logged = '1';
    }}
    async function doLogout() {{
      if (MODE === 'leaky_before_logout') {{
        localStorage.removeItem('token');
        sessionStorage.removeItem('profileEmail');
      }}
      document.documentElement.dataset.aut08LogoutDone = '1';
    }}
  </script>
</body>
</html>""".encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_doc)))
                    self.end_headers()
                    self.wfile.write(html_doc)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                p = self.path.split("?", 1)[0]
                if p == "/rest/user/login":
                    body = json.dumps({"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIzNDU"}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", "sid=httponly_cookie_val; Path=/; HttpOnly")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Aut08Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_aut8:
            tdp = Path(td_aut8)
            try:
                # 1. Compliant HttpOnly-only app via real Headless Chrome CDP -> PASS + redacted dump & HAR
                _Aut08Handler.mode = "clean_httponly"
                rep_pass = tdp / "aut08_pass.json"
                har_pass = tdp / "aut08_pass.har"
                r_pass = evaluate_aut08_client_storage(
                    f"http://127.0.0.1:{port}",
                    credentials=("canary_aut08@example.com", "CanaryPass!88"),
                    canaries=["canary_aut08@example.com", "CanaryPass!88"],
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertTrue(r_pass["headlessExecuted"], f"Expected real Chrome headless run, got {r_pass}")
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertEqual(r_pass["postLogoutSurvivors"], 0)
                self.assertTrue(rep_pass.exists())
                self.assertTrue(har_pass.exists())

                # 2. JWT in localStorage + canary email in sessionStorage before logout via real Headless Chrome -> FAIL
                _Aut08Handler.mode = "leaky_before_logout"
                rep_leak = tdp / "aut08_leak.json"
                r_leak = evaluate_aut08_client_storage(
                    f"http://127.0.0.1:{port}",
                    credentials=("canary_aut08@example.com", "CanaryPass!88"),
                    canaries=["canary_aut08@example.com", "CanaryPass!88"],
                    report_out_path=rep_leak,
                    har_out_path=tdp / "aut08_leak.har",
                )
                self.assertTrue(r_leak["headlessExecuted"])
                self.assertEqual(r_leak["verdict"], "FAIL")
                stores_hit = {(f["phase"], f["store"], f["key"]) for f in r_leak["findings"]}
                self.assertIn(("before_logout", "localStorage", "token"), stores_hit)
                self.assertIn(("before_logout", "sessionStorage", "profileEmail"), stores_hit)
                rep_txt = rep_leak.read_text(encoding="utf-8")
                self.assertIn("[REDACTED", rep_txt)
                self.assertNotIn("c2lnbmF0dXJlMTIzNDU", rep_txt)

                # 3. Auth material persists AFTER logout via real Headless Chrome -> FAIL
                _Aut08Handler.mode = "survives_logout"
                r_surv = evaluate_aut08_client_storage(
                    f"http://127.0.0.1:{port}",
                    credentials=("canary_aut08@example.com", "CanaryPass!88"),
                    canaries=["secret_surviving_token_value"],
                    report_out_path=tdp / "aut08_surv.json",
                    har_out_path=tdp / "aut08_surv.har",
                )
                self.assertTrue(r_surv["headlessExecuted"])
                self.assertEqual(r_surv["verdict"], "FAIL")
                self.assertGreaterEqual(r_surv["postLogoutSurvivors"], 1)
                self.assertTrue(any(s["ruleId"] == "CASA3-AUT-08" for s in r_surv["sarifResults"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 43/61: AUT-08 (Iteração SDD 113)", just2_txt)

    def test_iteration114_azi01_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_azi01_anti_csrf

        class _Azi01Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "session_bound"
            username = "initial_user"

            def log_message(self, fmt, *args):
                pass

            def _read_body(self) -> str:
                length = int(self.headers.get("Content-Length", "0"))
                return self.rfile.read(length).decode("utf-8", errors="ignore") if length else ""

            def _get_session_user(self) -> str:
                ck = self.headers.get("Cookie", "")
                for part in ck.split(";"):
                    if part.strip().startswith("token="):
                        val = part.split("=", 1)[1].strip()
                        if val == "tok_session_a":
                            return "sessA"
                        if val == "tok_session_b":
                            return "sessB"
                return ""

            def do_GET(self):
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                sess = self._get_session_user() or "anon"
                if p == "/profile":
                    csrf_tok = f"csrf_for_{sess}"
                    html_doc = (
                        f'<html><body>User:{type(self).username}'
                        f'<form method="POST"><input type="hidden" name="_csrf" value="{csrf_tok}"></form>'
                        f"</body></html>"
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("X-CSRF-Token", csrf_tok)
                    if m == "global_csrf_samesite_none":
                        self.send_header("Set-Cookie", "token=tok_session_a; Path=/; SameSite=None; Secure")
                    else:
                        self.send_header("Set-Cookie", "token=tok_session_a; Path=/; HttpOnly; SameSite=Strict")
                    self.send_header("Content-Length", str(len(html_doc)))
                    self.end_headers()
                    self.wfile.write(html_doc)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                raw = self._read_body()
                p = self.path.split("?", 1)[0]
                m = type(self).mode
                if p == "/rest/user/login":
                    try:
                        cred = json.loads(raw or "{}")
                    except Exception:
                        cred = {}
                    tok = "tok_session_b" if "admin" in cred.get("email", "") else "tok_session_a"
                    body = json.dumps({"authentication": {"token": tok}}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if p == "/profile":
                    sess = self._get_session_user()
                    parsed_form = urllib.parse.parse_qs(raw)
                    presented_csrf = self.headers.get("X-CSRF-Token", "") or (parsed_form.get("_csrf", [""])[0])
                    if not sess:
                        self.send_response(401)
                        self.end_headers()
                        return
                    allowed = False
                    if m == "session_bound":
                        allowed = presented_csrf == f"csrf_for_{sess}"
                    elif m == "no_csrf":
                        allowed = True
                    elif m == "global_csrf_samesite_none":
                        allowed = presented_csrf.startswith("csrf_for_")
                    if allowed and "username" in parsed_form:
                        type(self).username = parsed_form["username"][0]
                        body = b'{"status":"updated"}'
                        self.send_response(200)
                    else:
                        body = b'{"error":"Invalid CSRF token"}'
                        self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Azi01Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_azi1:
            tdp = Path(td_azi1)
            try:
                # 1. Session-bound anti-CSRF rejecting removed, replaced, and Session B CSRF token -> PASS + redacted HAR
                _Azi01Handler.mode = "session_bound"
                _Azi01Handler.username = "initial_user"
                har_pass = tdp / "azi01_pass.har"
                r_pass = evaluate_azi01_anti_csrf(
                    f"http://127.0.0.1:{port}",
                    session_a_token="tok_session_a",
                    session_b_token="tok_session_b",
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertEqual(r_pass["replaysExecuted"], 3)
                self.assertEqual(r_pass["sessionBCsrfToken"], "csrf_for_sessB")
                har_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("tok_session_a", har_txt)

                # 2. Unprotected endpoint mutating state across all 3 replay modes -> FAIL
                _Azi01Handler.mode = "no_csrf"
                r_nocsrf = evaluate_azi01_anti_csrf(
                    f"http://127.0.0.1:{port}",
                    session_a_token="tok_session_a",
                    session_b_token="tok_session_b",
                    har_out_path=tdp / "azi01_nocsrf.har",
                )
                self.assertEqual(r_nocsrf["verdict"], "FAIL")
                modes_hit = {f["mode"] for f in r_nocsrf["findings"]}
                self.assertTrue({"csrf_token_removed", "csrf_token_replaced", "csrf_token_second_session"}.issubset(modes_hit))

                # 3. Non-session-bound CSRF accepting Session B CSRF token + SameSite=None cookie -> FAIL (CASA3-AZI-01)
                _Azi01Handler.mode = "global_csrf_samesite_none"
                r_glob = evaluate_azi01_anti_csrf(
                    f"http://127.0.0.1:{port}",
                    session_a_token="tok_session_a",
                    session_b_token="tok_session_b",
                    har_out_path=tdp / "azi01_glob.har",
                )
                self.assertEqual(r_glob["verdict"], "FAIL")
                glob_modes = {f["mode"] for f in r_glob["findings"]}
                self.assertIn("csrf_token_second_session", glob_modes)
                self.assertIn("samesite_none_cookie", glob_modes)
                self.assertTrue(any(s["ruleId"] == "CASA3-AZI-01" for s in r_glob["sarifResults"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 44/61: AZI-01 (Iteração SDD 114)", just2_txt)

    def test_iteration115_azi02_guide_tooling(self) -> None:
        import html
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_azi02_xss

        class _Azi02Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "escaped"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p, _, q = self.path.partition("?")
                qs = urllib.parse.parse_qs(q)
                val = qs.get("q", [""])[0]
                m = type(self).mode
                if p == "/":
                    b = b'<html><body><a href="/rest/products/search?q=apple">search</a></body></html>'
                    st = 200
                elif p == "/rest/products/search":
                    rendered = html.escape(val) if m == "escaped" else val
                    b = f"<html><body>Results for: {rendered}</body></html>".encode("utf-8")
                    st = 200
                else:
                    b = b"Not found"
                    st = 404
                self.send_response(st)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Azi02Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_azi2:
            tdp = Path(td_azi2)
            try:
                # 1. Properly HTML-escaped search endpoint -> PASS via real OWASP ZAP 40012/40014 + Headless Chrome OOB listener
                _Azi02Handler.mode = "escaped"
                rep_pass = tdp / "azi02_pass.json"
                har_pass = tdp / "azi02_pass.har"
                r_pass = evaluate_azi02_xss(
                    f"http://127.0.0.1:{port}",
                    browser_urls_fn=lambda cb_port: [
                        f"http://127.0.0.1:{port}/rest/products/search?q="
                        + urllib.parse.quote(f"<img src=x onerror=\"fetch('http://127.0.0.1:{cb_port}/cb?vec=dom_search')\">")
                    ],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/rest/products/search?q=apple"],
                    zap_json_out_path=tdp / "zap_xss_pass.json",
                    zap_sarif_out_path=tdp / "zap_xss_pass.sarif",
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["zap"]["executed"])
                self.assertEqual(r_pass["callbacksReceived"], [])
                self.assertTrue(rep_pass.exists())
                self.assertTrue(har_pass.exists())

                # 2. Unescaped reflected XSS -> FAIL confirmed by BOTH real OWASP ZAP 40012 AND live Headless Chrome OOB HTTP callback
                _Azi02Handler.mode = "vulnerable_xss"
                rep_vuln = tdp / "azi02_vuln.json"
                har_vuln = tdp / "azi02_vuln.har"
                r_vuln = evaluate_azi02_xss(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_xss_tok_12345"},
                    browser_urls_fn=lambda cb_port: [
                        f"http://127.0.0.1:{port}/rest/products/search?q="
                        + urllib.parse.quote(f"<img src=x onerror=\"fetch('http://127.0.0.1:{cb_port}/cb?vec=dom_search')\">")
                    ],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/rest/products/search?q=apple"],
                    zap_json_out_path=tdp / "zap_xss_vuln.json",
                    zap_sarif_out_path=tdp / "zap_xss_vuln.sarif",
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                self.assertGreaterEqual(len(r_vuln["callbacksReceived"]), 1, f"Expected live OOB callback, got {r_vuln}")
                self.assertIn("40012", r_vuln["zapPluginsMatched"], f"Expected ZAP 40012, got {r_vuln}")
                self.assertTrue(any(f["confirmedBy"] == "out_of_band_http_callback" for f in r_vuln["findings"]))
                self.assertTrue(any(s["ruleId"] == "CASA3-AZI-02" for s in r_vuln["sarifResults"]))
                har_txt = har_vuln.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("secret_xss_tok_12345", har_txt)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 45/61: AZI-02 (Iteração SDD 115)", just2_txt)

    def test_iteration116_azi03_guide_tooling(self) -> None:
        import sqlite3
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_azi03_sqli_nosql

        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.execute("CREATE TABLE products (id INT, name TEXT)")
        db.executemany("INSERT INTO products VALUES (?, ?)", [(1, "apple"), (2, "banana"), (3, "cherry")])
        db.commit()
        db_lock = threading.Lock()

        class _Azi03Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "safe"

            def log_message(self, fmt, *args):
                pass

            def _send_json(self, st: int, obj: dict) -> None:
                b = json.dumps(obj).encode("utf-8")
                self.send_response(st)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                p, _, q = self.path.partition("?")
                qs = urllib.parse.parse_qs(q)
                term = qs.get("q", [""])[0]
                m = type(self).mode
                if p == "/":
                    b = b'<html><body><a href="/rest/products/search?q=apple">search</a></body></html>'
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                elif p == "/rest/products/search":
                    try:
                        with db_lock:
                            if m == "vulnerable":
                                rows = db.execute(f"SELECT id, name FROM products WHERE name = '{term}'").fetchall()
                            else:
                                rows = db.execute("SELECT id, name FROM products WHERE name = ?", (term,)).fetchall()
                        self._send_json(200, {"data": [{"id": r[0], "name": r[1]} for r in rows]})
                    except Exception as exc:
                        self._send_json(500, {"error": f"SQLITE_ERROR: {exc}"})
                elif p.startswith("/rest/track-order/"):
                    oid = urllib.parse.unquote(p[len("/rest/track-order/"):])
                    if m == "vulnerable" and "|| true ||" in oid:
                        self._send_json(200, {"data": [{"orderId": "1"}, {"orderId": "2"}, {"orderId": "3"}]})
                    elif oid == "ORD-1":
                        self._send_json(200, {"data": [{"orderId": "ORD-1"}]})
                    else:
                        self._send_json(200, {"data": []})
                else:
                    self._send_json(404, {"error": "not found"})

            def do_POST(self):
                cl = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(cl) if cl > 0 else b"{}"
                try:
                    payload = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
                except Exception:
                    payload = {}
                m = type(self).mode
                if self.path == "/rest/user/login":
                    email = payload.get("email", "")
                    if m == "vulnerable" and isinstance(email, dict):
                        self._send_json(200, {"authentication": {"token": "jwt_mock_tok", "umail": "admin@test.local"}})
                    elif m == "vulnerable" and isinstance(email, str) and "' or 1=1" in email.lower():
                        self._send_json(200, {"authentication": {"token": "jwt_mock_tok", "umail": "admin@test.local"}})
                    else:
                        self._send_json(401, {"error": "Invalid email or password."})
                elif self.path == "/api/nosql-search":
                    qv = payload.get("q", "")
                    if isinstance(qv, dict):
                        if m == "vulnerable" and any(op in qv for op in ("$ne", "$regex", "$gt")):
                            self._send_json(200, {"data": [{"id": 1}, {"id": 2}]})
                        else:
                            self._send_json(400, {"error": "NoSQL operators rejected"})
                    else:
                        self._send_json(200, {"data": []})
                else:
                    self._send_json(404, {"error": "not found"})

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Azi03Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_azi3:
            tdp = Path(td_azi3)
            try:
                # 1. Parameterized SQLite + rejected NoSQL operators -> PASS via real sqlmap + real OWASP ZAP 40018/40024 + NoSQL probes
                _Azi03Handler.mode = "safe"
                rep_pass = tdp / "azi03_pass.json"
                har_pass = tdp / "azi03_pass.har"
                r_pass = evaluate_azi03_sqli_nosql(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_sqli_tok_98765"},
                    sqlmap_targets=[f"http://127.0.0.1:{port}/rest/products/search?q=apple"],
                    nosql_query_targets=[{"path": "/api/nosql-search", "param": "q"}],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/rest/products/search?q=apple"],
                    zap_json_out_path=tdp / "zap_sqli_pass.json",
                    zap_sarif_out_path=tdp / "zap_sqli_pass.sarif",
                    sqlmap_out_path=tdp / "sqlmap_pass.json",
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["sqlmap"]["executed"])
                self.assertEqual(r_pass["sqlmap"]["injectableParameters"], [])
                self.assertTrue(r_pass["zap"]["executed"])
                self.assertTrue(rep_pass.exists())
                self.assertTrue(har_pass.exists())

                # 2. Vulnerable SQLite concatenation + NoSQL $where/$ne alteration -> FAIL confirmed by sqlmap + OWASP ZAP + NoSQL differential checks
                _Azi03Handler.mode = "vulnerable"
                rep_vuln = tdp / "azi03_vuln.json"
                har_vuln = tdp / "azi03_vuln.har"
                r_vuln = evaluate_azi03_sqli_nosql(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_sqli_tok_98765"},
                    sqlmap_targets=[f"http://127.0.0.1:{port}/rest/products/search?q=apple"],
                    nosql_query_targets=[{"path": "/api/nosql-search", "param": "q"}],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/rest/products/search?q=apple"],
                    zap_json_out_path=tdp / "zap_sqli_vuln.json",
                    zap_sarif_out_path=tdp / "zap_sqli_vuln.sarif",
                    sqlmap_out_path=tdp / "sqlmap_vuln.json",
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                self.assertGreaterEqual(len(r_vuln["sqlmap"]["injectableParameters"]), 1, f"Expected sqlmap SQLi detection, got {r_vuln['sqlmap']}")
                self.assertTrue(any(p in {"40018", "40024"} for p in r_vuln["zapPluginsMatched"]), f"Expected ZAP 40018/40024, got {r_vuln['zapPluginsMatched']}")
                vtypes = {f["vulnType"] for f in r_vuln["findings"]}
                self.assertIn("sqlmap_SQLi", vtypes)
                self.assertIn("NoSQL_Where_Result_Altered", vtypes)
                self.assertIn("NoSQL_Operator_Result_Altered_$ne", vtypes)
                self.assertTrue(any(s["ruleId"] == "CASA3-AZI-03" for s in r_vuln["sarifResults"]))
                har_txt = har_vuln.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("secret_sqli_tok_98765", har_txt)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 46/61: AZI-03 (Iteração SDD 116)", just2_txt)

    def test_iteration117_azi04_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_azi04_cmd_injection

        class _Azi04Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "safe"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p, _, q = self.path.partition("?")
                qs = urllib.parse.parse_qs(q)
                term = qs.get("q", [""])[0]
                m = type(self).mode
                if p == "/":
                    b = b'<html><body><a href="/rest/products/search?q=apple">search</a></body></html>'
                    st = 200
                elif p == "/rest/products/search":
                    if m == "vulnerable":
                        try:
                            cp = subprocess.run(
                                ["/bin/sh", "-c", f"echo ping_{term}"],
                                capture_output=True,
                                text=True,
                                timeout=3,
                            )
                            b = ((cp.stdout or "") + (cp.stderr or "")).encode("utf-8", errors="ignore")
                        except Exception as exc:
                            b = str(exc).encode("utf-8")
                    else:
                        b = f"safe_echo: {term}".encode("utf-8")
                    st = 200
                else:
                    b = b"Not found"
                    st = 404
                self.send_response(st)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Azi04Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_azi4:
            tdp = Path(td_azi4)
            try:
                # 1. Safe parameterized response -> PASS via real OWASP ZAP 90020 + OOB HTTP/DNS listeners
                _Azi04Handler.mode = "safe"
                rep_pass = tdp / "azi04_pass.json"
                har_pass = tdp / "azi04_pass.har"
                r_pass = evaluate_azi04_cmd_injection(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_cmdi_tok_54321"},
                    param_targets=[("GET", "/rest/products/search?q={p}", "query:q")],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/rest/products/search?q=apple"],
                    zap_json_out_path=tdp / "zap_cmdi_pass.json",
                    zap_sarif_out_path=tdp / "zap_cmdi_pass.sarif",
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["zap"]["executed"])
                self.assertEqual(r_pass["httpCallbacks"], [])
                self.assertEqual(r_pass["dnsCallbacks"], [])
                self.assertTrue(rep_pass.exists())
                self.assertTrue(har_pass.exists())

                # 2. Vulnerable shell invocation -> FAIL confirmed by real OWASP ZAP 90020 + uid= output + HTTP OOB + DNS OOB
                _Azi04Handler.mode = "vulnerable"
                rep_vuln = tdp / "azi04_vuln.json"
                har_vuln = tdp / "azi04_vuln.har"
                r_vuln = evaluate_azi04_cmd_injection(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_cmdi_tok_54321"},
                    param_targets=[("GET", "/rest/products/search?q={p}", "query:q")],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/rest/products/search?q=apple"],
                    zap_json_out_path=tdp / "zap_cmdi_vuln.json",
                    zap_sarif_out_path=tdp / "zap_cmdi_vuln.sarif",
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                self.assertIn("90020", r_vuln["zapPluginsMatched"], f"Expected ZAP 90020, got {r_vuln['zapPluginsMatched']}")
                self.assertGreaterEqual(len(r_vuln["httpCallbacks"]), 1, f"Expected live HTTP OOB callback, got {r_vuln}")
                self.assertGreaterEqual(len(r_vuln["dnsCallbacks"]), 1, f"Expected live DNS OOB callback, got {r_vuln}")
                cby = {f["confirmedBy"] for f in r_vuln["findings"]}
                self.assertIn("command_output_marker", cby)
                self.assertIn("oob_http_callback", cby)
                self.assertIn("oob_dns_callback", cby)
                self.assertTrue(any(s["ruleId"] == "CASA3-AZI-04" for s in r_vuln["sarifResults"]))
                har_txt = har_vuln.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("secret_cmdi_tok_54321", har_txt)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 47/61: AZI-04 (Iteração SDD 117)", just2_txt)

    def test_iteration118_azi05_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_azi05_lfi_rfi

        class _Azi05Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "safe"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p, _, q = self.path.partition("?")
                qs = urllib.parse.parse_qs(q)
                raw_file = qs.get("file", [""])[0]
                m = type(self).mode
                if p == "/":
                    b = b'<html><body><a href="/view?file=readme.txt">view</a></body></html>'
                    st = 200
                elif p == "/view":
                    decoded_twice = urllib.parse.unquote(urllib.parse.unquote(raw_file))
                    if m == "vulnerable":
                        if decoded_twice.startswith("http://127.0.0.1:") or decoded_twice.startswith("https://"):
                            try:
                                with urllib.request.urlopen(decoded_twice, timeout=2) as rf:
                                    b = rf.read(4096)
                                    st = 200
                            except Exception:
                                b = b"upstream error"
                                st = 502
                        elif "passwd" in decoded_twice or ".." in decoded_twice:
                            b = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                            st = 200
                        else:
                            b = b"Public doc contents"
                            st = 200
                    else:
                        if any(bad in decoded_twice for bad in ("..", "/", "\\", "\x00", "http:", "https:")):
                            b = b"Forbidden path or scheme"
                            st = 403
                        else:
                            b = b"Public doc contents"
                            st = 200
                else:
                    b = b"Not found"
                    st = 404
                self.send_response(st)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Azi05Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_azi5:
            tdp = Path(td_azi5)
            try:
                # 1. Strict canonical path & scheme validation -> PASS via real OWASP ZAP 6/7 + traversal & RFI matrix
                _Azi05Handler.mode = "safe"
                rep_pass = tdp / "azi05_pass.json"
                har_pass = tdp / "azi05_pass.har"
                r_pass = evaluate_azi05_lfi_rfi(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_lfi_tok_24680"},
                    param_targets=[("view", "/view?file={p}")],
                    rfi_targets=["/view?file={p}"],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/view?file=readme.txt"],
                    zap_json_out_path=tdp / "zap_lfi_pass.json",
                    zap_sarif_out_path=tdp / "zap_lfi_pass.sarif",
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["zap"]["executed"])
                self.assertEqual(r_pass["rfiCallbacks"], [])
                self.assertTrue(rep_pass.exists())
                self.assertTrue(har_pass.exists())

                # 2. Vulnerable traversal + RFI -> FAIL confirmed by real OWASP ZAP (6/7), traversal leak & RFI callback+marker
                _Azi05Handler.mode = "vulnerable"
                rep_vuln = tdp / "azi05_vuln.json"
                har_vuln = tdp / "azi05_vuln.har"
                r_vuln = evaluate_azi05_lfi_rfi(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_lfi_tok_24680"},
                    param_targets=[("view", "/view?file={p}")],
                    rfi_targets=["/view?file={p}"],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/view?file=readme.txt"],
                    zap_json_out_path=tdp / "zap_lfi_vuln.json",
                    zap_sarif_out_path=tdp / "zap_lfi_vuln.sarif",
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                self.assertTrue(any(p in {"6", "7"} for p in r_vuln["zapPluginsMatched"]), f"Expected ZAP 6 or 7, got {r_vuln['zapPluginsMatched']}")
                self.assertGreaterEqual(len(r_vuln["rfiCallbacks"]), 1, f"Expected live RFI callback, got {r_vuln}")
                cby = {f["confirmedBy"] for f in r_vuln["findings"]}
                self.assertIn("traversal_probe", cby)
                self.assertTrue("rfi_inclusion_marker" in cby or "rfi_oob_fetch" in cby)
                self.assertTrue(any(s["ruleId"] == "CASA3-AZI-05" for s in r_vuln["sarifResults"]))
                har_txt = har_vuln.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("secret_lfi_tok_24680", har_txt)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 48/61: AZI-05 (Iteração SDD 118)", just2_txt)

    def test_iteration119_azi06_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_azi06_open_redirect_hpp

        class _Azi06Handler(BaseHTTPRequestHandler):
            timeout = 2
            mode = "safe"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p, _, q = self.path.partition("?")
                qs = urllib.parse.parse_qs(q)
                to_vals = qs.get("to", [])
                m = type(self).mode
                if p == "/":
                    b = b'<html><body><a href="/redirect?to=https://github.com/juice-shop/juice-shop">redir</a></body></html>'
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                elif p == "/redirect":
                    first_to = to_vals[0] if to_vals else ""
                    if m == "vulnerable":
                        # Simulates Juice Shop substring .includes("github.com") + HPP array coercion
                        if any("github.com" in v for v in to_vals) or len(to_vals) == 1 and ("evil.example.com" in first_to or first_to.startswith("//")):
                            self.send_response(302)
                            self.send_header("Location", first_to or "https://evil.example.com")
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                            return
                        b = b"Unrecognized target URL for redirect"
                        self.send_response(406)
                        self.send_header("Content-Length", str(len(b)))
                        self.end_headers()
                        self.wfile.write(b)
                    else:
                        if len(to_vals) != 1:
                            b = b"Duplicate redirect parameter rejected"
                            self.send_response(400)
                            self.send_header("Content-Length", str(len(b)))
                            self.end_headers()
                            self.wfile.write(b)
                            return
                        h = (urllib.parse.urlparse(first_to).hostname or "").lower()
                        if h == "github.com" and first_to.startswith("https://"):
                            self.send_response(302)
                            self.send_header("Location", first_to)
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                        else:
                            b = b"Blocked off-allowlist redirect"
                            self.send_response(406)
                            self.send_header("Content-Length", str(len(b)))
                            self.end_headers()
                            self.wfile.write(b)
                elif p == "/js-redir":
                    if m == "vulnerable":
                        b = b"<html><script>window.location.href = 'https://evil.example.com/phish';</script></html>"
                    else:
                        b = b"<html><body>OK</body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                else:
                    b = b"Unauthorized"
                    self.send_response(401)
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Azi06Handler)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_azi6:
            tdp = Path(td_azi6)
            try:
                # 1. Strict hostname allowlist & duplicate param rejection -> PASS via real OWASP ZAP 20019/20014 + NoRedirect/HPP harness
                _Azi06Handler.mode = "safe"
                rep_pass = tdp / "azi06_pass.json"
                har_pass = tdp / "azi06_pass.har"
                r_pass = evaluate_azi06_open_redirect_hpp(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_redir_tok_13579"},
                    zap_seed_urls=[f"http://127.0.0.1:{port}/redirect?to=https://github.com/juice-shop/juice-shop"],
                    zap_json_out_path=tdp / "zap_redir_pass.json",
                    zap_sarif_out_path=tdp / "zap_redir_pass.sarif",
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertTrue(r_pass["zap"]["executed"])
                self.assertTrue(rep_pass.exists())
                self.assertTrue(har_pass.exists())

                # 2. Substring/off-allowlist open redirect + JS redirect -> FAIL confirmed by real OWASP ZAP 20019 + NoRedirect harness + redacted HAR
                _Azi06Handler.mode = "vulnerable"
                rep_vuln = tdp / "azi06_vuln.json"
                har_vuln = tdp / "azi06_vuln.har"
                r_vuln = evaluate_azi06_open_redirect_hpp(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_redir_tok_13579"},
                    redirect_targets=[
                        ("direct_off_allowlist", "/redirect?to=https://evil.example.com"),
                        ("query_substring_bypass", "/redirect?to=https://evil.example.com?https://github.com/juice-shop/juice-shop"),
                        ("js_redirect", "/js-redir?next=https://evil.example.com"),
                    ],
                    zap_seed_urls=[f"http://127.0.0.1:{port}/redirect?to=https://github.com/juice-shop/juice-shop"],
                    zap_json_out_path=tdp / "zap_redir_vuln.json",
                    zap_sarif_out_path=tdp / "zap_redir_vuln.sarif",
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                self.assertIn("20019", r_vuln["zapPluginsMatched"], f"Expected ZAP 20019, got {r_vuln['zapPluginsMatched']}")
                kinds = {f["kind"] for f in r_vuln["findings"]}
                self.assertIn("OpenRedirect_query_substring_bypass", kinds)
                self.assertIn("OpenRedirect_js_redirect", kinds)
                self.assertTrue(any(s["ruleId"] == "CASA3-AZI-06" for s in r_vuln["sarifResults"]))
                har_txt = har_vuln.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("secret_redir_tok_13579", har_txt)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 49/61: AZI-06 (Iteração SDD 119)", just2_txt)

    def test_iteration120_oau01_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_oau01_grant_type

        class _MockOAuthServer(BaseHTTPRequestHandler):
            timeout = 2

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p, _, q = self.path.partition("?")
                if p == "/oauth/authorize":
                    self.send_response(302)
                    self.send_header("Location", "https://app.example.com/callback?code=auth_code_999&state=xyz")
                    self.send_header("Set-Cookie", "idp_sess=idp_secret_111; HttpOnly")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")

            def do_POST(self):
                cl = int(self.headers.get("Content-Length", "0") or 0)
                _ = self.rfile.read(cl) if cl > 0 else b""
                b = json.dumps({"access_token": "tok_ok", "token_type": "Bearer"}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockOAuthServer)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_oau1:
            tdp = Path(td_oau1)
            safe_repo = tdp / "safe_repo"
            (safe_repo / "src").mkdir(parents=True)
            (safe_repo / "src" / "oauth.ts").write_text(
                'export const AUTH_URL = "https://idp.example.com/authorize?response_type=code&client_id=c1";\n'
                'export const TOKEN_BODY = { grant_type: "authorization_code" };\n',
                encoding="utf-8",
            )
            vuln_repo = tdp / "vuln_repo"
            (vuln_repo / "src").mkdir(parents=True)
            (vuln_repo / "src" / "ropc.py").write_text(
                'import requests\n'
                'def login_ropc(user, pw):\n'
                '    return requests.post("https://idp.example.com/token", data={"grant_type": "password", "username": user, "password": pw})\n',
                encoding="utf-8",
            )
            try:
                # 1. Proxied Authorization Code flow + clean source -> PASS
                rep_pass = tdp / "oau01_pass.json"
                har_pass = tdp / "oau01_pass.har"
                sg_pass = tdp / "oau01_pass_sg.sarif"
                r_pass = evaluate_oau01_grant_type(
                    f"http://127.0.0.1:{port}",
                    repo=safe_repo,
                    oauth_flow_requests=[
                        {"url": f"http://127.0.0.1:{port}/oauth/authorize?response_type=code&client_id=c1", "method": "GET"},
                        {
                            "url": f"http://127.0.0.1:{port}/oauth/token",
                            "method": "POST",
                            "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Bearer secret_bearer_01"},
                            "body": "grant_type=authorization_code&code=secret_auth_code_99&client_secret=secret_cs_77",
                        },
                    ],
                    semgrep_out_path=sg_pass,
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertEqual(len(r_pass["proxiedRequests"]), 2)
                self.assertTrue(r_pass["semgrepExecuted"])
                self.assertEqual(r_pass["semgrepHits"], 0)
                har_pass_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_pass_txt)
                self.assertNotIn("secret_auth_code_99", har_pass_txt)
                self.assertNotIn("secret_cs_77", har_pass_txt)
                self.assertNotIn("secret_bearer_01", har_pass_txt)
                self.assertNotIn("idp_secret_111", har_pass_txt)

                # 2. Hybrid response_type + ROPC proxied flow + Semgrep grant_type=password -> FAIL
                rep_vuln = tdp / "oau01_vuln.json"
                har_vuln = tdp / "oau01_vuln.har"
                sg_vuln = tdp / "oau01_vuln_sg.sarif"
                r_vuln = evaluate_oau01_grant_type(
                    f"http://127.0.0.1:{port}",
                    repo=vuln_repo,
                    oauth_flow_requests=[
                        {"url": f"http://127.0.0.1:{port}/oauth/authorize?response_type=code%20id_token&client_id=c1", "method": "GET"},
                        {
                            "url": f"http://127.0.0.1:{port}/oauth/token",
                            "method": "POST",
                            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                            "body": "grant_type=password&username=alice&password=super_secret_pw_777",
                        },
                    ],
                    semgrep_out_path=sg_vuln,
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                self.assertGreaterEqual(r_vuln["semgrepHits"], 1, f"Expected real Semgrep ROPC hit, got {r_vuln}")
                cby = {f["confirmedBy"] for f in r_vuln["findings"]}
                gvs = {f["grantViolation"] for f in r_vuln["findings"]}
                self.assertIn("intercepting_proxy", cby)
                self.assertIn("semgrep", cby)
                self.assertIn("response_type=code id_token", gvs)
                self.assertIn("grant_type=password", gvs)
                self.assertTrue(any(s["ruleId"] == "CASA3-OAU-01" for s in r_vuln["sarifResults"]))
                har_vuln_txt = har_vuln.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_vuln_txt)
                self.assertNotIn("super_secret_pw_777", har_vuln_txt)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 50/61: OAU-01 (Iteração SDD 120)", just2_txt)

    def test_iteration121_oau02_guide_tooling(self) -> None:
        import base64
        import hashlib
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_oau02_pkce

        verifier_ok = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_secret_verifier_99"
        challenge_ok = base64.urlsafe_b64encode(hashlib.sha256(verifier_ok.encode("ascii")).digest()).decode("ascii").rstrip("=")

        class _PkceMockServer(BaseHTTPRequestHandler):
            timeout = 2
            mode = "strict"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://app.example.com/callback?code=pkce_code_01&state=s1")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):
                cl = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(cl).decode("utf-8", errors="ignore") if cl > 0 else ""
                fp = urllib.parse.parse_qs(raw)
                cv = (fp.get("code_verifier") or [""])[0]
                if type(self).mode == "strict" and cv != verifier_ok:
                    b = json.dumps({"error": "invalid_grant", "error_description": "PKCE verifier mismatch"}).encode("utf-8")
                    self.send_response(400)
                else:
                    b = json.dumps({"access_token": "tok_pkce_ok", "token_type": "Bearer"}).encode("utf-8")
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _PkceMockServer)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_oau2:
            tdp = Path(td_oau2)
            safe_repo = tdp / "safe_repo"
            (safe_repo / "src").mkdir(parents=True)
            (safe_repo / "src" / "pkce_ok.ts").write_text(
                'export const AUTH_URI = `https://idp.example.com/authorize?client_id=c1&redirect_uri=https://app.example.com/cb&response_type=code&code_challenge=${cc}&code_challenge_method=S256`;\n'
                'export const TOKEN_REQ = { grant_type: "authorization_code", code_verifier: verifier };\n',
                encoding="utf-8",
            )
            weak_repo = tdp / "weak_repo"
            (weak_repo / "src").mkdir(parents=True)
            (weak_repo / "src" / "pkce_weak.ts").write_text(
                'export const WEAK_AUTH = "https://idp.example.com/authorize?client_id=c1&redirect_uri=https://app.example.com/cb&response_type=code&code_challenge=abc&code_challenge_method=plain";\n',
                encoding="utf-8",
            )
            try:
                # 1. Valid S256 code_challenge (>= 43 chars) + matching code_verifier + negative probe rejected -> PASS
                _PkceMockServer.mode = "strict"
                rep_pass = tdp / "oau02_pass.json"
                har_pass = tdp / "oau02_pass.har"
                sg_pass = tdp / "oau02_pass_sg.sarif"
                r_pass = evaluate_oau02_pkce(
                    f"http://127.0.0.1:{port}",
                    repo=safe_repo,
                    oauth_flow_requests=[
                        {
                            "url": f"http://127.0.0.1:{port}/oauth/authorize?response_type=code&client_id=c1&code_challenge={challenge_ok}&code_challenge_method=S256",
                            "method": "GET",
                        },
                        {
                            "url": f"http://127.0.0.1:{port}/oauth/token",
                            "method": "POST",
                            "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Bearer secret_pkce_auth_1"},
                            "body": f"grant_type=authorization_code&code=pkce_code_01&code_verifier={verifier_ok}",
                        },
                    ],
                    negative_token_probe={
                        "url": f"http://127.0.0.1:{port}/oauth/token",
                        "method": "POST",
                        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                        "body": "grant_type=authorization_code&code=pkce_code_01",
                    },
                    semgrep_out_path=sg_pass,
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertEqual(len(r_pass["proxiedRequests"]), 3)
                self.assertTrue(r_pass["semgrepExecuted"])
                self.assertEqual(r_pass["semgrepHits"], 0)
                har_pass_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_pass_txt)
                self.assertNotIn(verifier_ok, har_pass_txt)
                self.assertNotIn("secret_pkce_auth_1", har_pass_txt)

                # 2. plain method + short challenge + mismatched verifier + verifier bypass + Semgrep hit -> FAIL
                _PkceMockServer.mode = "weak"
                rep_vuln = tdp / "oau02_vuln.json"
                har_vuln = tdp / "oau02_vuln.har"
                sg_vuln = tdp / "oau02_vuln_sg.sarif"
                r_vuln = evaluate_oau02_pkce(
                    f"http://127.0.0.1:{port}",
                    repo=weak_repo,
                    oauth_flow_requests=[
                        {
                            "url": f"http://127.0.0.1:{port}/oauth/authorize?response_type=code&client_id=c1&code_challenge=short123&code_challenge_method=plain",
                            "method": "GET",
                        },
                        {
                            "url": f"http://127.0.0.1:{port}/oauth/token",
                            "method": "POST",
                            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                            "body": "grant_type=authorization_code&code=pkce_code_01&code_verifier=wrong_verifier_value",
                        },
                    ],
                    negative_token_probe={
                        "url": f"http://127.0.0.1:{port}/oauth/token",
                        "method": "POST",
                        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                        "body": "grant_type=authorization_code&code=pkce_code_01",
                    },
                    semgrep_out_path=sg_vuln,
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                self.assertGreaterEqual(r_vuln["semgrepHits"], 1, f"Expected Semgrep OAU-02 hit, got {r_vuln}")
                cby = {f["confirmedBy"] for f in r_vuln["findings"]}
                self.assertIn("intercepting_proxy", cby)
                self.assertIn("intercepting_proxy_pkce_crypto", cby)
                self.assertIn("pkce_verifier_bypass", cby)
                self.assertIn("semgrep", cby)
                self.assertTrue(any(s["ruleId"] == "CASA3-OAU-02" for s in r_vuln["sarifResults"]))
                har_vuln_txt = har_vuln.read_text(encoding="utf-8")
                self.assertNotIn("wrong_verifier_value", har_vuln_txt)
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 51/61: OAU-02 (Iteração SDD 121)", just2_txt)

    def test_iteration122_oau03_guide_tooling(self) -> None:
        from http.server import BaseHTTPRequestHandler
        from casa_audit.scanner import evaluate_oau03_redirect_uris

        class _Oau03Server(BaseHTTPRequestHandler):
            timeout = 2
            mode = "safe"

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                p, _, q = self.path.partition("?")
                qs = urllib.parse.parse_qs(q)
                m = type(self).mode
                if p == "/oauth/authorize":
                    self.send_response(302)
                    self.send_header("Location", "https://app.example.com/callback?code=auth_secret_03&state=s1")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif p == "/callback":
                    if m == "vulnerable":
                        nxt = (qs.get("next") or [""])[0]
                        if nxt:
                            self.send_response(302)
                            self.send_header("Location", nxt)
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                            return
                    b = b"Callback blocked unallowlisted target"
                    self.send_response(400)
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                else:
                    b = b"ok"
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Oau03Server)
        srv.daemon_threads = True
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td_oau3:
            tdp = Path(td_oau3)
            try:
                # 1. Exact HTTPS + loopback redirect_uri + hardened /callback -> PASS
                _Oau03Server.mode = "safe"
                rep_pass = tdp / "oau03_pass.json"
                har_pass = tdp / "oau03_pass.har"
                r_pass = evaluate_oau03_redirect_uris(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_oau03_tok_111"},
                    oauth_sources=[("src/oauth.ts", 'const R = "redirect_uri=http%3A%2F%2F127.0.0.1%3A4200%2Fcb";')],
                    oauth_flow_requests=[
                        {"url": f"http://127.0.0.1:{port}/oauth/authorize?response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback", "method": "GET"}
                    ],
                    callback_paths=["/callback"],
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", f"Expected PASS, got {r_pass}")
                self.assertGreaterEqual(len(r_pass["proxiedRequests"]), 1)
                self.assertIn("https://app.example.com/callback", r_pass["observedRedirects"])
                self.assertEqual(r_pass["loopbackHttpCount"], 1)
                har_pass_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_pass_txt)
                self.assertNotIn("secret_oau03_tok_111", har_pass_txt)
                self.assertNotIn("auth_secret_03", har_pass_txt)

                # 2. Wildcard + non-loopback http: + callback open redirect on ?next= -> FAIL
                _Oau03Server.mode = "vulnerable"
                rep_vuln = tdp / "oau03_vuln.json"
                har_vuln = tdp / "oau03_vuln.har"
                r_vuln = evaluate_oau03_redirect_uris(
                    f"http://127.0.0.1:{port}",
                    auth_headers={"Authorization": "Bearer secret_oau03_tok_111"},
                    oauth_sources=[
                        ("config.yml", 'redirect_uri=https://*.example.com/cb redirect_uri=http://dev.remote.local/cb'),
                    ],
                    oauth_flow_requests=[
                        {"url": f"http://127.0.0.1:{port}/oauth/authorize?response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback", "method": "GET"}
                    ],
                    callback_paths=["/callback"],
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                kinds = {f["kind"] for f in r_vuln["findings"]}
                self.assertIn("Wildcard_Redirect_URI", kinds)
                self.assertIn("NonLoopback_HTTP_Redirect_URI", kinds)
                self.assertIn("Callback_Open_Redirect_direct", kinds)
                self.assertTrue(any(s["ruleId"] == "CASA3-OAU-03" for s in r_vuln["sarifResults"]))
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 52/61: OAU-03 (Iteração SDD 122)", just2_txt)

    def test_iteration123_oau04_guide_tooling(self) -> None:
        import http.server
        import json
        import secrets
        import socketserver
        import tempfile
        import threading
        import urllib.parse

        from casa_audit.scanner import evaluate_oau04_state_nonce

        class _Oau04Server(http.server.BaseHTTPRequestHandler):
            mode = "hardened"
            counter = 0

            def log_message(self, format, *args) -> None:
                return

            def do_GET(self) -> None:
                p = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(p.query)
                if p.path == "/oauth/authorize":
                    _Oau04Server.counter += 1
                    if _Oau04Server.mode == "hardened":
                        st = secrets.token_urlsafe(32)
                        nn = secrets.token_urlsafe(24)
                    else:
                        st = f"weak_{_Oau04Server.counter % 5}"
                        nn = "static_nonce"
                    self.send_response(302)
                    self.send_header(
                        "Location",
                        f"https://idp.example.com/auth?response_type=code&scope=openid&state={st}&nonce={nn}",
                    )
                    self.end_headers()
                    return
                if p.path == "/oauth":
                    if _Oau04Server.mode == "hardened":
                        self.send_response(403)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error":"invalid_state_or_nonce"}')
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Set-Cookie", "token=eyJ_accepted_without_state; HttpOnly; Secure")
                    self.end_headers()
                    self.wfile.write(b'{"access_token":"eyJ_replayed"}')
                    return
                self.send_response(404)
                self.end_headers()

        class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        srv = _ThreadedHTTPServer(("127.0.0.1", 0), _Oau04Server)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            src_dir = tdp / "frontend" / "src" / "app"
            src_dir.mkdir(parents=True)
            hardened_ts = src_dir / "login.component.ts"
            hardened_ts.write_text(
                "const st = crypto.randomUUID(); const nn = crypto.randomUUID();\n"
                "const u = `https://idp.example.com/auth?client_id=c1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid&state=${st}&nonce=${nn}`;\n",
                encoding="utf-8",
            )

            try:
                # 1. Hardened: 200 distinct CSPRNG states >=128 bits, strict callback rejection -> PASS
                rep_pass = tdp / "oau04_pass.json"
                har_pass = tdp / "oau04_pass.har"
                sg_pass = tdp / "oau04_pass_sg.sarif"
                r_pass = evaluate_oau04_state_nonce(
                    f"http://127.0.0.1:{port}",
                    repo=tdp,
                    auth_headers={"Authorization": "Bearer secret_oau04_tok_999", "Cookie": "sid=auth_secret_04"},
                    oauth_sources=[("login.component.ts", hardened_ts.read_text(encoding="utf-8"))],
                    report_out_path=rep_pass,
                    har_out_path=har_pass,
                    semgrep_sarif_out_path=sg_pass,
                )
                self.assertEqual(r_pass["verdict"], "PASS", r_pass["findings"])
                self.assertEqual(r_pass["stateSamples"], 200)
                self.assertEqual(r_pass["distinctStates"], 200)
                self.assertGreaterEqual(r_pass["minEntropyBits"], 128.0)
                self.assertTrue(r_pass["oidcNonceChecked"])
                self.assertEqual(r_pass["semgrepHits"], 0)
                har_pass_txt = har_pass.read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_pass_txt)
                self.assertNotIn("secret_oau04_tok_999", har_pass_txt)
                self.assertNotIn("auth_secret_04", har_pass_txt)

                # 2. Vulnerable: duplicate/low-entropy state + callback accepts replays/nonce omit + Semgrep hits -> FAIL
                _Oau04Server.mode = "vulnerable"
                vuln_ts = src_dir / "login.component.ts"
                vuln_ts.write_text(
                    "const u = 'https://idp.example.com/auth?client_id=c1&redirect_uri=https://app.example.com/cb&scope=openid';\n",
                    encoding="utf-8",
                )
                rep_vuln = tdp / "oau04_vuln.json"
                har_vuln = tdp / "oau04_vuln.har"
                sg_vuln = tdp / "oau04_vuln_sg.sarif"
                r_vuln = evaluate_oau04_state_nonce(
                    f"http://127.0.0.1:{port}",
                    repo=tdp,
                    auth_headers={"Authorization": "Bearer secret_oau04_tok_999"},
                    oauth_sources=[("login.component.ts", vuln_ts.read_text(encoding="utf-8"))],
                    report_out_path=rep_vuln,
                    har_out_path=har_vuln,
                    semgrep_sarif_out_path=sg_vuln,
                )
                self.assertEqual(r_vuln["verdict"], "FAIL")
                kinds = {f["kind"] for f in r_vuln["findings"]}
                self.assertIn("Repeated_OAuth_State", kinds)
                self.assertIn("Insufficient_State_MinEntropy", kinds)
                self.assertIn("Callback_Accepted_state_omitted", kinds)
                self.assertIn("Callback_Accepted_nonce_omitted", kinds)
                self.assertIn("Missing_OAuth_State_Parameter", kinds)
                self.assertIn("Missing_OIDC_Nonce_Parameter", kinds)
                self.assertGreaterEqual(r_vuln["semgrepHits"], 1)
                self.assertTrue(any(s["ruleId"] == "CASA3-OAU-04" for s in r_vuln["sarifResults"]))
                rep_data = json.loads(rep_vuln.read_text(encoding="utf-8"))
                self.assertIn("nonce_omitted:/oauth", rep_data["callbackReplays"])
            finally:
                srv.shutdown()
                srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 53/61: OAU-04 (Iteração SDD 123)", just2_txt)

    def test_iteration124_oau05_guide_tooling(self) -> None:
        import http.server
        import socketserver
        import tempfile
        import threading
        import zipfile

        from casa_audit.scanner import evaluate_oau05_system_browser

        class _IdpStub(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", "myapp://cb?code=c1")
                self.end_headers()

        class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        srv = _ThreadedHTTPServer(("127.0.0.1", 0), _IdpStub)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as td:
                tdp = Path(td)
                # 1. Hardened mobile client: CustomTabsIntent + ASWebAuthenticationSession + clean APK ZIP -> PASS
                pass_repo = tdp / "pass_mobile"
                (pass_repo / "android").mkdir(parents=True)
                (pass_repo / "ios").mkdir(parents=True)
                (pass_repo / "android" / "OAuthLogin.kt").write_text(
                    'val url = "https://idp.example.com/authorize?client_id=c1"\n'
                    'CustomTabsIntent.Builder().build().launchUrl(ctx, Uri.parse(url))\n',
                    encoding="utf-8",
                )
                (pass_repo / "ios" / "AuthSession.swift").write_text(
                    'let s = ASWebAuthenticationSession(url: authURL, callbackURLScheme: "myapp") { _, _ in }\n',
                    encoding="utf-8",
                )
                with zipfile.ZipFile(pass_repo / "app-release.apk", "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("AndroidManifest.xml", "<manifest package='org.safe.app'/>")
                    zf.writestr("classes.dex", b"CustomTabsIntent oauth2 authorize")

                r_pass = evaluate_oau05_system_browser(
                    f"http://127.0.0.1:{port}",
                    repo=pass_repo,
                    oauth_flow_requests=[
                        {
                            "url": f"http://127.0.0.1:{port}/oauth/authorize?client_id=c1&response_type=code",
                            "method": "GET",
                            "headers": {
                                "User-Agent": "Mozilla/5.0 (Linux; Android 14) Chrome/124.0 Mobile Safari/537.36",
                                "Authorization": "Bearer secret_oau05_hdr",
                            },
                        }
                    ],
                    report_out_path=tdp / "oau05_pass.json",
                    har_out_path=tdp / "oau05_pass.har",
                    semgrep_sarif_out_path=tdp / "oau05_pass_sg.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", r_pass["findings"])
                self.assertGreaterEqual(r_pass["binCount"], 1)
                self.assertIn("CustomTabsIntent", r_pass["approvedHits"])
                self.assertEqual(r_pass["semgrepHits"], 0)
                har_txt = (tdp / "oau05_pass.har").read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn("secret_oau05_hdr", har_txt)

                # 2. Vulnerable: zipped .apk with compressed WebView + Kotlin WebView + Swift SFSafariViewController + HAR ; wv) UA -> FAIL
                fail_repo = tdp / "fail_mobile"
                (fail_repo / "android").mkdir(parents=True)
                (fail_repo / "ios").mkdir(parents=True)
                (fail_repo / "android" / "LegacyAuth.kt").write_text(
                    'val web = WebView(ctx)\nweb.loadUrl("https://idp.example.com/authorize?client_id=c1")\n',
                    encoding="utf-8",
                )
                (fail_repo / "ios" / "LegacyAuth.swift").write_text(
                    'let vc = SFSafariViewController(url: URL(string: "https://idp.example.com/oauth2/authorize")!)\n',
                    encoding="utf-8",
                )
                with zipfile.ZipFile(fail_repo / "app-debug.apk", "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("classes.dex", b"android.webkit.WebView loadUrl https://idp.example.com/oauth/authorize")

                r_fail = evaluate_oau05_system_browser(
                    f"http://127.0.0.1:{port}",
                    repo=fail_repo,
                    oauth_flow_requests=[
                        {
                            "url": f"http://127.0.0.1:{port}/oauth/authorize?client_id=c1&response_type=code",
                            "method": "GET",
                            "headers": {"User-Agent": "Mozilla/5.0 (Linux; Android 13; wv) AppleWebKit/537.36 Version/4.0 Chrome/120.0"},
                        }
                    ],
                    report_out_path=tdp / "oau05_fail.json",
                    har_out_path=tdp / "oau05_fail.har",
                    semgrep_sarif_out_path=tdp / "oau05_fail_sg.sarif",
                )
                self.assertEqual(r_fail["verdict"], "FAIL")
                kinds = {f["kind"] for f in r_fail["findings"]}
                self.assertIn("Android_WebView", kinds)
                self.assertIn("iOS_SFSafariViewController", kinds)
                self.assertIn("HAR_Embedded_WebView_UserAgent", kinds)
                self.assertIn("Semgrep_OAU05_Embedded_WebView", kinds)
                self.assertGreaterEqual(r_fail["semgrepHits"], 2)
                self.assertTrue(any(s["ruleId"] == "CASA3-OAU-05" for s in r_fail["sarifResults"]))

                # 3. Web-only repo -> Not_Covered (never fake PASS)
                web_repo = tdp / "web_only"
                web_repo.mkdir()
                (web_repo / "index.ts").write_text("console.log('spa web app');", encoding="utf-8")
                r_nc = evaluate_oau05_system_browser(
                    "",
                    repo=web_repo,
                    report_out_path=tdp / "oau05_nc.json",
                    har_out_path=tdp / "oau05_nc.har",
                    semgrep_sarif_out_path=tdp / "oau05_nc_sg.sarif",
                )
                self.assertEqual(r_nc["verdict"], "Not_Covered")
        finally:
            srv.shutdown()
            srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 54/61: OAU-05 (Iteração SDD 124)", just2_txt)

    def test_iteration125_oau06_guide_tooling(self) -> None:
        import http.server
        import json
        import socketserver
        import tempfile
        import threading
        import urllib.parse
        import zipfile

        from casa_audit.scanner import evaluate_oau06_client_secrets

        leaked_secret = "GOCSPX-RealSecretLeakedInApk9988"

        class _TokenStub(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8", errors="ignore")
                form = urllib.parse.parse_qs(body)
                if form.get("client_secret", [""])[0] == leaked_secret:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"access_token":"eyJ_minted_by_leaked_secret"}')
                    return
                self.send_response(401)
                self.end_headers()

        class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        srv = _ThreadedHTTPServer(("127.0.0.1", 0), _TokenStub)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        try:
            with tempfile.TemporaryDirectory() as td:
                tdp = Path(td)
                # 1. Hardened public client: PKCE Kotlin + clean zipped APK + no secret -> PASS
                pass_repo = tdp / "pass_public_client"
                (pass_repo / "android").mkdir(parents=True)
                (pass_repo / "android" / "AuthConfig.kt").write_text(
                    'const val clientId = "mob-public-pkce-125"\n'
                    'const val placeholderSecret = "replace_me"\n',
                    encoding="utf-8",
                )
                with zipfile.ZipFile(pass_repo / "public-safe.apk", "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("AndroidManifest.xml", "<manifest package='org.safe.public'/>")
                    zf.writestr("classes.dex", b"client_id=mob-public-pkce-125 pkce S256")

                r_pass = evaluate_oau06_client_secrets(
                    f"http://127.0.0.1:{port}",
                    repo=pass_repo,
                    report_out_path=tdp / "oau06_pass.json",
                    har_out_path=tdp / "oau06_pass.har",
                    semgrep_sarif_out_path=tdp / "oau06_pass_sg.sarif",
                )
                self.assertEqual(r_pass["verdict"], "PASS", r_pass["findings"])
                self.assertIn("mob-public-pkce-125", r_pass["clientIds"])
                self.assertEqual(r_pass["semgrepHits"], 0)

                # 2. Vulnerable: compressed .apk with GOCSPX- + Kotlin literal client_secret + IdP accepts -> FAIL
                fail_repo = tdp / "fail_public_client"
                (fail_repo / "android").mkdir(parents=True)
                (fail_repo / "android" / "LeakedAuth.kt").write_text(
                    f'const val client_id = "mob-leaked-125"\n'
                    f'const val client_secret = "{leaked_secret}"\n'
                    f'const val tokenUrl = "http://127.0.0.1:{port}/oauth/token"\n',
                    encoding="utf-8",
                )
                with zipfile.ZipFile(fail_repo / "app-leaked.apk", "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("classes.dex", f'client_id="mob-leaked-125" client_secret="{leaked_secret}"'.encode("utf-8"))

                r_fail = evaluate_oau06_client_secrets(
                    f"http://127.0.0.1:{port}",
                    repo=fail_repo,
                    report_out_path=tdp / "oau06_fail.json",
                    har_out_path=tdp / "oau06_fail.har",
                    semgrep_sarif_out_path=tdp / "oau06_fail_sg.sarif",
                )
                self.assertEqual(r_fail["verdict"], "FAIL")
                kinds = {f["kind"] for f in r_fail["findings"]}
                self.assertIn("Known_IdP_Client_Secret", kinds)
                self.assertIn("Embedded_Client_Secret_Key", kinds)
                self.assertIn("Token_Endpoint_Accepted_Embedded_Secret", kinds)
                self.assertIn("Semgrep_OAU06_Embedded_Client_Secret", kinds)
                har_txt = (tdp / "oau06_fail.har").read_text(encoding="utf-8")
                self.assertIn("[REDACTED]", har_txt)
                self.assertNotIn(leaked_secret, har_txt)
                self.assertTrue(any(s["ruleId"] == "CASA3-OAU-06" for s in r_fail["sarifResults"]))

                # 3. Web-only repo -> Not_Covered
                web_repo = tdp / "web_only"
                web_repo.mkdir()
                (web_repo / "app.ts").write_text("const clientId = 'web-spa-01';", encoding="utf-8")
                r_nc = evaluate_oau06_client_secrets(
                    "",
                    repo=web_repo,
                    report_out_path=tdp / "oau06_nc.json",
                    har_out_path=tdp / "oau06_nc.har",
                    semgrep_sarif_out_path=tdp / "oau06_nc_sg.sarif",
                )
                self.assertEqual(r_nc["verdict"], "Not_Covered")
        finally:
            srv.shutdown()
            srv.server_close()

        just2_txt = (ROOT_DIR / "docs" / "justificativa2.txt").read_text(encoding="utf-8")
        self.assertIn("CONTROLE 55/61: OAU-06 (Iteração SDD 125)", just2_txt)


if __name__ == "__main__":
    unittest.main()

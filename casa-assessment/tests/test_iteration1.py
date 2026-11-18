"""Automated tests for Iteration 1: CASA 3.0 Assessment Tool (SDD 001-casa3-assessment)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from casa_audit.scanner import (
    compute_cvss3_base_score,
    compute_levenshtein_distance,
    compute_shannon_entropy,
    evaluate_oau05_system_browser_policy,
    evaluate_oau06_client_secret_scanner,
    load_controls,
    run_automated_al1_scan,
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


if __name__ == "__main__":
    unittest.main()

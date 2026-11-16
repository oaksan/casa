"""Automated tests for Iteration 1: CASA 3.0 Assessment Tool (SDD 001-casa3-assessment)."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from casa_audit.scanner import load_controls, run_automated_al1_scan
from casa_audit.server import CasaAssessmentHandler

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_JSON = ROOT_DIR / "casa-assessment" / "data" / "casa3_controls.json"
FRONTEND_DIR = ROOT_DIR / "casa-assessment" / "frontend"


class TestCasa3Iteration1(unittest.TestCase):
    def test_dataset_has_61_al1_and_15_al2_controls(self) -> None:
        self.assertTrue(DATA_JSON.exists(), "casa3_controls.json must exist")
        payload = json.loads(DATA_JSON.read_text(encoding="utf-8"))
        controls = payload["controls"]
        self.assertEqual(len(controls), 76)

        al1 = [c for c in controls if c["tier"] == "AL1"]
        al2 = [c for c in controls if c["tier"] == "AL2"]
        self.assertEqual(len(al1), 61)
        self.assertEqual(len(al2), 15)

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
                self.assertIn("data.js", html)
                self.assertIn("app.js", html)

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
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(body["status"], "ok")
                self.assertEqual(body["count"], 61)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()

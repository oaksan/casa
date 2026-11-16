"""HTTP Server serving the CASA 3.0 Assessment Frontend and `/api/scan` endpoint."""

from __future__ import annotations

import argparse
import functools
import http.server
import json
from pathlib import Path

from casa_audit.scanner import load_controls, run_automated_al1_scan

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


class CasaAssessmentHandler(http.server.SimpleHTTPRequestHandler):
    """Serves static files from `frontend/` plus `/api/scan` and `/api/controls`."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self.path = "/assess.html"
            return super().do_GET()
        if self.path == "/api/controls":
            controls = load_controls()
            self._send_json(200, {"count": len(controls), "controls": controls})
            return
        return super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            try:
                body = json.loads(raw)
            except Exception:
                body = {}
            target_url = body.get("target_url", "")
            repo_path = body.get("repo_path", "")
            surfaces = body.get("surfaces", ["Web_Application"])
            results = run_automated_al1_scan(
                target_url=target_url,
                repo_path=repo_path,
                surfaces=surfaces,
            )
            self._send_json(200, {"status": "ok", "count": len(results), "results": results})
            return
        self._send_json(404, {"error": "Not found"})

    def _send_json(self, status: int, payload: dict) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the ADA CASA 3.0 Assessment Web UI & Scanner API.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    args = parser.parse_args(argv)

    server = http.server.ThreadingHTTPServer((args.host, args.port), CasaAssessmentHandler)
    print(f"ADA CASA 3.0 Assessment UI running at: http://{args.host}:{args.port}/assess.html")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()


if __name__ == "__main__":
    main()

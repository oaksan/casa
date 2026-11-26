"""HTTP Server serving the CASA 3.0 Assessment Frontend and `/api/scan` endpoints."""

from __future__ import annotations

import argparse
import http.server
import importlib
import json
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

import casa_audit.scanner
from casa_audit.scanner import load_controls

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"

DOMAIN_SPEC: list[tuple[str, int]] = [
    ("SCA", 5),
    ("SAST", 13),
    ("TLS", 6),
    ("CFG", 11),
    ("AUT", 8),
    ("AZI", 6),
    ("OAU", 9),
    ("WHK", 3),
]
TOTAL_AL1_CONTROLS = sum(cnt for _, cnt in DOMAIN_SPEC)

_SCAN_LOCK = threading.Lock()
_SCAN_JOBS: dict[str, dict] = {}
_MAX_SCAN_JOBS = 20


def _build_initial_job(scan_id: str, target_url: str, repo_path: str, surfaces: list[str]) -> dict:
    return {
        "scan_id": scan_id,
        "status": "running",
        "target_url": target_url,
        "repo_path": repo_path,
        "surfaces": list(surfaces),
        "started_at": time.monotonic(),
        "finished_at": None,
        "current_domain": "SCA",
        "stage_pt": "Iniciando scan automatizado AL1 (61 controles em 8 domínios)…",
        "stage_en": "Starting automated AL1 scan (61 controls across 8 domains)…",
        "last_control": "",
        "last_verdict": "",
        "last_tool": "",
        "seen_controls": {},
        "domains": {
            dom: {"done": 0, "total": cnt, "status": "pending", "pass": 0, "fail": 0}
            for dom, cnt in DOMAIN_SPEC
        },
        "recent_events": [],
        "error": None,
        "results": None,
    }


def _recompute_job_metrics(job: dict) -> dict:
    seen: dict[str, str] = job["seen_controls"]
    counts = {"PASS": 0, "FAIL": 0, "NOT_APPLICABLE": 0, "Not_Covered": 0}
    dom_stats: dict[str, dict] = {}
    for dom, total_d in DOMAIN_SPEC:
        d_items = [(cid, v) for cid, v in seen.items() if cid.startswith(f"{dom}-")]
        done_d = len(d_items)
        pass_d = sum(1 for _, v in d_items if v == "PASS")
        fail_d = sum(1 for _, v in d_items if v == "FAIL")
        if job["status"] == "completed" or done_d >= total_d:
            d_status = "done"
        elif job["current_domain"] == dom or done_d > 0:
            d_status = "running"
        else:
            d_status = "pending"
        dom_stats[dom] = {
            "done": min(done_d, total_d),
            "total": total_d,
            "status": d_status,
            "pass": pass_d,
            "fail": fail_d,
        }
    for v in seen.values():
        if v in counts:
            counts[v] += 1
        elif v:
            counts[v] = counts.get(v, 0) + 1

    completed = min(len(seen), TOTAL_AL1_CONTROLS)
    if job["status"] == "completed":
        completed = len(job["results"] or seen) or TOTAL_AL1_CONTROLS
    percent = 100 if job["status"] == "completed" else min(99, int(round((completed / max(1, TOTAL_AL1_CONTROLS)) * 100)))
    end_ts = job["finished_at"] if job["finished_at"] is not None else time.monotonic()
    elapsed_sec = round(max(0.0, end_ts - job["started_at"]), 1)

    return {
        "completed": completed,
        "total": TOTAL_AL1_CONTROLS,
        "percent": percent,
        "elapsed_sec": elapsed_sec,
        "current_domain": job["current_domain"],
        "stage_pt": job["stage_pt"],
        "stage_en": job["stage_en"],
        "last_control": job["last_control"],
        "last_verdict": job["last_verdict"],
        "last_tool": job["last_tool"],
        "counts": counts,
        "domains": dom_stats,
        "domain_order": [dom for dom, _ in DOMAIN_SPEC],
        "recent_events": list(job["recent_events"][-8:]),
    }


def start_async_scan_job(target_url: str, repo_path: str, surfaces: list[str]) -> tuple[str, dict]:
    """Start an automated AL1 scan in a background thread and return (scan_id, initial_progress)."""
    scan_id = uuid.uuid4().hex[:12]
    job = _build_initial_job(scan_id, target_url, repo_path, surfaces)
    with _SCAN_LOCK:
        active_running = any(j["status"] == "running" for j in _SCAN_JOBS.values())
        if len(_SCAN_JOBS) >= _MAX_SCAN_JOBS:
            oldest = sorted(_SCAN_JOBS.items(), key=lambda kv: kv[1]["started_at"])
            for old_id, old_j in oldest:
                if old_j["status"] != "running":
                    _SCAN_JOBS.pop(old_id, None)
                    if len(_SCAN_JOBS) < _MAX_SCAN_JOBS:
                        break
        _SCAN_JOBS[scan_id] = job
        initial_progress = _recompute_job_metrics(job)

    if not active_running:
        try:
            importlib.reload(casa_audit.scanner)
        except Exception:
            pass

    def _on_progress(event: dict) -> None:
        ev_type = event.get("type")
        with _SCAN_LOCK:
            if ev_type == "stage":
                dom = str(event.get("domain") or job["current_domain"])
                job["current_domain"] = dom
                if event.get("stage_pt"):
                    job["stage_pt"] = str(event["stage_pt"])
                if event.get("stage_en"):
                    job["stage_en"] = str(event["stage_en"])
            elif ev_type == "control":
                cid = str(event.get("control_id") or "")
                verdict = str(event.get("verdict") or "")
                tool = str(event.get("tool") or "")
                dom = str(event.get("domain") or (cid.split("-", 1)[0] if "-" in cid else ""))
                if cid:
                    job["seen_controls"][cid] = verdict
                    job["last_control"] = cid
                    job["last_verdict"] = verdict
                    job["last_tool"] = tool[:120]
                    if dom:
                        job["current_domain"] = dom
                    job["recent_events"].append(
                        {
                            "control_id": cid,
                            "domain": dom,
                            "verdict": verdict,
                            "tool": tool[:90],
                            "elapsed_sec": round(max(0.0, time.monotonic() - job["started_at"]), 1),
                        }
                    )
                    if len(job["recent_events"]) > 20:
                        job["recent_events"] = job["recent_events"][-20:]

    def _worker() -> None:
        try:
            results = casa_audit.scanner.run_automated_al1_scan(
                target_url=target_url,
                repo_path=repo_path,
                surfaces=surfaces,
                progress_cb=_on_progress,
            )
            with _SCAN_LOCK:
                for cid, res in results.items():
                    if isinstance(res, dict):
                        job["seen_controls"][cid] = str(res.get("verdict") or "")
                job["results"] = results
                job["status"] = "completed"
                job["current_domain"] = "DONE"
                job["stage_pt"] = f"Scan concluído — {len(results)} controles AL1 avaliados."
                job["stage_en"] = f"Scan completed — {len(results)} AL1 controls evaluated."
                job["finished_at"] = time.monotonic()
        except Exception as exc:
            with _SCAN_LOCK:
                job["status"] = "error"
                job["error"] = str(exc)
                job["stage_pt"] = f"Erro durante o scan: {exc}"
                job["stage_en"] = f"Error during scan: {exc}"
                job["finished_at"] = time.monotonic()

    threading.Thread(target=_worker, name=f"casa-scan-{scan_id}", daemon=True).start()
    return scan_id, initial_progress


def get_scan_job_snapshot(scan_id: str) -> dict | None:
    """Return a JSON-serializable status snapshot for an async scan job."""
    with _SCAN_LOCK:
        job = _SCAN_JOBS.get(scan_id)
        if job is None:
            return None
        progress = _recompute_job_metrics(job)
        payload: dict = {
            "scan_id": scan_id,
            "status": job["status"],
            "progress": progress,
        }
        if job["status"] == "error":
            payload["error"] = job["error"] or "Unknown scan error"
        if job["status"] == "completed" and job["results"] is not None:
            payload["count"] = len(job["results"])
            payload["results"] = job["results"]
        return payload


class CasaAssessmentHandler(http.server.SimpleHTTPRequestHandler):
    """Serves static files from `frontend/` plus `/api/scan`, `/api/scan/start`, `/api/scan/status`, and `/api/controls`."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        super().end_headers()

    def do_GET(self) -> None:
        if "If-Modified-Since" in self.headers:
            del self.headers["If-Modified-Since"]
        if "If-None-Match" in self.headers:
            del self.headers["If-None-Match"]
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self.path = "/assess.html"
            return super().do_GET()
        if parsed.path == "/api/controls":
            controls = load_controls()
            self._send_json(200, {"count": len(controls), "controls": controls})
            return
        if parsed.path == "/api/scan/status":
            qs = urllib.parse.parse_qs(parsed.query)
            scan_id = (qs.get("id") or [""])[0].strip()
            snap = get_scan_job_snapshot(scan_id) if scan_id else None
            if snap is None:
                self._send_json(404, {"error": "Scan job not found", "scan_id": scan_id})
                return
            self._send_json(200, snap)
            return
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/api/scan", "/api/scan/start"}:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            try:
                body = json.loads(raw)
            except Exception:
                body = {}
            target_url = body.get("target_url", "")
            repo_path = body.get("repo_path", "")
            surfaces = body.get("surfaces", ["Web_Application"])

            if parsed.path == "/api/scan/start":
                scan_id, initial_progress = start_async_scan_job(target_url, repo_path, surfaces)
                self._send_json(
                    202,
                    {
                        "status": "running",
                        "scan_id": scan_id,
                        "progress": initial_progress,
                    },
                )
                return

            with _SCAN_LOCK:
                active_running = any(j["status"] == "running" for j in _SCAN_JOBS.values())
            if not active_running:
                importlib.reload(casa_audit.scanner)
            results = casa_audit.scanner.run_automated_al1_scan(
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

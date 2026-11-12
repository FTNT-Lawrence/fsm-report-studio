#!/usr/bin/env python3
"""網頁控制台：填 Supervisor IP 同 API Access Key，揀報告版本／顏色，然後產生報告。

本機預設只綁 127.0.0.1。若設定了 PORT 或 RENDER（例如雲端部署），改為綁 0.0.0.0 並使用該連接埠。
Access Key 只在記憶體傳送一次給子行程的環境變數，絕不寫入磁碟。
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

STUDIO = Path(__file__).resolve().parent
WEB = STUDIO / "web"
OUT = STUDIO / "out"
WORK = STUDIO / "work"
GENERATE = STUDIO / "generate.py"
PY = sys.executable

if str(STUDIO / "engine") not in sys.path:
    sys.path.insert(0, str(STUDIO / "engine"))
from studio_lib import redact  # noqa: E402

PREFERRED_PORT = 8765


def is_hosted() -> bool:
    return bool(os.environ.get("RENDER") or os.environ.get("PORT"))

_lock = threading.Lock()
_job = {
    "running": False,
    "lines": [],
    "ok": None,
    "error": None,
    "filename": None,
    "path": None,
    "bytes": None,
    "started": None,
    "finished": None,
}


def pick_port(host: str = "127.0.0.1", start: int = PREFERRED_PORT, end: int = 8799) -> int:
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
            except OSError:
                continue
            return port
    raise SystemExit("找不到可用連接埠（8765–8799）")


def _mime(path: Path) -> str:
    ext = path.suffix.lower()
    return {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
    }.get(ext, "application/octet-stream")


def _saved_data_status() -> dict:
    pulse = WORK / "fsm-v15-7d-data.json"
    full = WORK / "fsm-v15-7d-full-data.json"
    ot = WORK / "ot-collect.json"
    if not ot.is_file():
        cands = sorted(WORK.glob("ot*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        ot = cands[0] if cands else ot
    return {
        "siem": pulse.is_file() and full.is_file(),
        "ot": ot.is_file(),
        "siem_pulse": pulse.name if pulse.is_file() else None,
        "siem_full": full.name if full.is_file() else None,
        "ot_json": ot.name if ot.is_file() else None,
    }


def _validate(body: dict) -> str | None:
    from_data = bool(body.get("from_data"))
    kind = (body.get("kind") or "").strip()
    version = str(body.get("version") or "").strip()
    theme = (body.get("theme") or "").strip()
    lang = (body.get("lang") or "").strip()
    if kind not in ("siem", "ot"):
        return "請選擇報告種類（SIEM 或 OT/IoT）。"
    if version not in ("1.5", "1.3"):
        return "請選擇報告格式版本。"
    if theme not in ("light", "dark"):
        return "請選擇顏色主題。"
    if lang not in ("zh", "en"):
        return "請選擇報告語言。"
    if kind == "ot" and version == "1.3":
        return "OT/IoT 報告只支援格式 v1.5。經典 v1.3 僅適用於 SIEM。"
    if version == "1.3" and theme == "light":
        return "經典 v1.3 只有深色 cyber HUD 主題。請改選深色，或改用 v1.5。"
    if not from_data:
        if not (body.get("host") or "").strip():
            return "請填寫 Supervisor IP／主機。"
        if not (body.get("client_id") or "").strip():
            return "請填寫 OAuth Client ID（FortiSIEM MCP OAuth client id）。"
        if not (body.get("secret") or "").strip():
            return "請填寫 API Access Key／Client Secret。若要以已儲存數據重建，請勾選「用上次收集嘅 JSON 重建」。"
    else:
        saved = _saved_data_status()
        if kind == "siem" and not saved["siem"]:
            return "找不到上次收集嘅 SIEM JSON（work/fsm-v15-7d-data.json 同 fsm-v15-7d-full-data.json）。請先即時收集一次。"
        if kind == "ot" and not saved["ot"]:
            return "找不到上次收集嘅 OT JSON（work/ot-collect.json）。請先即時收集一次。"
    mode = (body.get("window_mode") or "days").strip()
    if mode == "absolute":
        if not (body.get("start") or "").strip():
            return "請填寫視窗開始日期（香港時間）。"
    else:
        try:
            days = float(body.get("days") or 0)
        except (TypeError, ValueError):
            return "回看日數必須係數字。"
        if days <= 0:
            return "回看日數必須大於 0。"
    return None


def _build_cmd(body: dict) -> list[str]:
    cmd = [
        PY, "-u", str(GENERATE),
        "--kind", body["kind"],
        "--version", str(body["version"]),
        "--theme", body["theme"],
        "--lang", body["lang"],
        "--workers", str(int(body.get("workers") or 2)),
        "--timeout", str(int(body.get("timeout") or 120)),
    ]
    if (body.get("host") or "").strip():
        cmd += ["--host", body["host"].strip()]
    if (body.get("client_id") or "").strip():
        cmd += ["--client-id", body["client_id"].strip()]
    if body.get("verify_tls"):
        cmd.append("--no-insecure")
    else:
        cmd.append("--insecure")
    if body.get("from_data"):
        cmd.append("--from-data")
    mode = (body.get("window_mode") or "days").strip()
    if mode == "absolute":
        cmd += ["--start", body["start"].strip()]
        if (body.get("end") or "").strip():
            cmd += ["--end", body["end"].strip()]
    else:
        cmd += ["--days", str(body.get("days"))]
    return cmd


def _run_job(body: dict) -> None:
    env = os.environ.copy()
    secret = (body.get("secret") or "").strip()
    if secret:
        env["FORTISIEM_CLIENT_SECRET"] = secret
    # Do not persist secret anywhere else.
    cmd = _build_cmd(body)
    proc = subprocess.Popen(
        cmd,
        cwd=str(STUDIO),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    result_path = None
    assert proc.stdout is not None
    for line in proc.stdout:
        line = redact(line.rstrip("\n"), extra=[secret] if secret else None)
        with _lock:
            _job["lines"].append(line)
            if len(_job["lines"]) > 4000:
                _job["lines"] = _job["lines"][-3000:]
        if line.startswith("RESULT "):
            result_path = line[len("RESULT "):].strip()
    rc = proc.wait()
    with _lock:
        _job["running"] = False
        _job["finished"] = time.time()
        if rc == 0 and result_path:
            path = Path(result_path)
            _job["ok"] = True
            _job["path"] = str(path)
            _job["filename"] = path.name
            _job["bytes"] = path.stat().st_size if path.is_file() else None
            _job["error"] = None
        else:
            _job["ok"] = False
            tail = "\n".join(_job["lines"][-20:]) if _job["lines"] else f"結束碼 {rc}"
            _job["error"] = redact(tail or f"產生失敗（結束碼 {rc}）", extra=[secret] if secret else None)


def start_job(body: dict) -> tuple[int, dict]:
    err = _validate(body)
    if err:
        return 400, {"ok": False, "error": err}
    with _lock:
        if _job["running"]:
            return 409, {"ok": False, "error": "已有一份報告喺度產生，請等佢完成。"}
        _job.update({
            "running": True,
            "lines": [],
            "ok": None,
            "error": None,
            "filename": None,
            "path": None,
            "bytes": None,
            "started": time.time(),
            "finished": None,
        })
    t = threading.Thread(target=_run_job, args=(body,), daemon=True)
    t.start()
    return 200, {"ok": True, "started": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "FSM-Report-Studio/1.0"

    def log_message(self, fmt, *args):
        msg = fmt % args
        if "secret" in msg.lower() or "access" in msg.lower():
            msg = redact(msg)
        sys.stderr.write("%s - %s\n" % (self.address_string(), msg))

    def _send(self, code: int, body: bytes, content_type: str, headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(code, raw, "application/json; charset=utf-8")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path in ("/", "/index.html"):
            target = WEB / "index.html"
            self._send(200, target.read_bytes(), _mime(target))
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            target = (WEB / rel).resolve()
            if not str(target).startswith(str(WEB.resolve())) or not target.is_file():
                self._json(404, {"ok": False, "error": "not found"})
                return
            self._send(200, target.read_bytes(), _mime(target))
            return
        if path == "/api/status":
            with _lock:
                snap = {
                    "running": _job["running"],
                    "lines": list(_job["lines"]),
                    "ok": _job["ok"],
                    "error": _job["error"],
                    "filename": _job["filename"],
                    "bytes": _job["bytes"],
                    "download": (f"/download/{_job['filename']}" if _job["filename"] else None),
                    "out_path": _job["path"],
                    "saved": _saved_data_status(),
                }
            self._json(200, snap)
            return
        if path == "/api/saved":
            self._json(200, {"ok": True, **_saved_data_status()})
            return
        if path.startswith("/download/"):
            name = path[len("/download/"):]
            if not name or "/" in name or "\\" in name or name.startswith("."):
                self._json(400, {"ok": False, "error": "無效檔名"})
                return
            target = (OUT / name).resolve()
            if not str(target).startswith(str(OUT.resolve())) or not target.is_file():
                self._json(404, {"ok": False, "error": "找不到該報告"})
                return
            data = target.read_bytes()
            self._send(
                200,
                data,
                "text/html; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="{name}"'},
            )
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            self._json(413, {"ok": False, "error": "請求太大"})
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            self._json(400, {"ok": False, "error": "無法解析 JSON 請求。"})
            return
        if not isinstance(body, dict):
            self._json(400, {"ok": False, "error": "請求格式不正確。"})
            return
        if path == "/api/generate":
            code, obj = start_job(body)
            self._json(code, obj)
            return
        self._json(404, {"ok": False, "error": "not found"})


def main() -> int:
    os.chdir(STUDIO)
    OUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    if not (WEB / "index.html").is_file():
        raise SystemExit(f"缺少網頁檔案：{WEB / 'index.html'}")
    hosted = is_hosted()
    if hosted:
        host = "0.0.0.0"
        port = int(os.environ["PORT"]) if os.environ.get("PORT") else PREFERRED_PORT
    else:
        host = "127.0.0.1"
        port = pick_port(host)
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"FortiSIEM Report Studio 已啟動：{url}", flush=True)
    if hosted:
        print(f"雲端模式：監聽 0.0.0.0:{port}。", flush=True)
    else:
        print("只監聽本機 127.0.0.1。按 Ctrl+C 結束。", flush=True)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。", flush=True)
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

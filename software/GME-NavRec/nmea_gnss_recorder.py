#!/usr/bin/env python3
"""
NMEA GNSS recorder (portable, web UI).

- Listens on UDP and TCP for NMEA0183 sentences (default UDP 10110, TCP 10111)
- Validates checksums, counts ok/bad, and stores recent lines
- Optionally logs to a timestamped file under logs/
- Serves http://127.0.0.1:8084 for control and live view

Pure stdlib; suitable for PyInstaller onefile builds.
"""

import argparse
import datetime
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse
import json

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8084
EVENTS_MAX = 400
LINES_KEEP = 500


def now_ts() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def validate_nmea(line: str) -> bool:
    line = line.strip()
    if not line.startswith("$") or "*" not in line:
        return False
    try:
        body, cks = line[1:].split("*", 1)
    except ValueError:
        return False
    calc = 0
    for ch in body:
        calc ^= ord(ch)
    try:
        provided = int(cks[:2], 16)
    except ValueError:
        return False
    return calc == provided


def log_event(level: str, msg: str) -> None:
    entry = {"ts": time.time(), "level": level, "msg": msg}
    with state_lock:
        events.append(entry)
        if len(events) > EVENTS_MAX:
            del events[: len(events) - EVENTS_MAX]


def get_local_ips() -> List[str]:
    ips: List[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0]
            if ":" in addr:
                continue
            if addr.startswith("127."):
                continue
            if addr not in ips:
                ips.append(addr)
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return ips


def choose_port(default_port: int, prompt: bool, arg_port: Optional[int]) -> int:
    if arg_port and 1 <= arg_port <= 65535:
        return arg_port
    if not prompt:
        return default_port
    try:
        user = input(f"Enter HTTP port [{default_port}]: ").strip()
        if user:
            val = int(user)
            if 1 <= val <= 65535:
                return val
    except Exception:
        pass
    return default_port


class RecorderState:
    def __init__(self):
        self.udp_port = 10110
        self.tcp_port = 10111
        self.running = False
        self.total = 0
        self.ok = 0
        self.bad = 0
        self.last_lines: List[Dict] = []
        self.log_file: Optional[str] = None
        self.log_handle: Optional[object] = None
        self._udp_thread: Optional[threading.Thread] = None
        self._tcp_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._tcp_sock: Optional[socket.socket] = None

    def to_dict(self) -> Dict:
        return {
            "udp_port": self.udp_port,
            "tcp_port": self.tcp_port,
            "running": self.running,
            "total": self.total,
            "ok": self.ok,
            "bad": self.bad,
            "log_file": self.log_file,
            "last": self.last_lines[-20:],
        }

    def configure(self, udp_port: Optional[int], tcp_port: Optional[int]) -> None:
        if udp_port:
            self.udp_port = int(udp_port)
        if tcp_port:
            self.tcp_port = int(tcp_port)
        log_event("info", f"Configured UDP {self.udp_port}, TCP {self.tcp_port}")

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self._open_log()
        self._udp_thread = threading.Thread(target=self._udp_loop, daemon=True)
        self._udp_thread.start()
        self._tcp_thread = threading.Thread(target=self._tcp_loop, daemon=True)
        self._tcp_thread.start()
        log_event("info", "Recorder started")

    def stop(self) -> None:
        self.running = False
        self._stop.set()
        if self._tcp_sock:
            try:
                self._tcp_sock.close()
            except Exception:
                pass
        self._close_log()
        log_event("info", "Recorder stopped")

    def _open_log(self) -> None:
        os.makedirs("logs", exist_ok=True)
        fname = f"logs/nmea_{int(time.time())}.log"
        try:
            self.log_handle = open(fname, "a", encoding="utf-8")
            self.log_file = fname
            log_event("info", f"Logging to {fname}")
        except Exception as exc:
            self.log_handle = None
            self.log_file = None
            log_event("error", f"Failed to open log file: {exc}")

    def _close_log(self) -> None:
        if self.log_handle:
            try:
                self.log_handle.close()
            except Exception:
                pass
            self.log_handle = None

    def _record_line(self, line: str, source: str) -> None:
        ok = validate_nmea(line)
        with state_lock:
            self.total += 1
            if ok:
                self.ok += 1
            else:
                self.bad += 1
            self.last_lines.append({"line": line.strip(), "ok": ok, "src": source, "ts": now_ts()})
            if len(self.last_lines) > LINES_KEEP:
                del self.last_lines[: len(self.last_lines) - LINES_KEEP]
        if self.log_handle:
            try:
                self.log_handle.write(f"{now_ts()} [{source}] {line.strip()}\n")
                self.log_handle.flush()
            except Exception:
                pass

    def _udp_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", self.udp_port))
        sock.settimeout(0.5)
        log_event("info", f"UDP listening on {self.udp_port}")
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for line in text.replace("\r", "\n").split("\n"):
                    if line.strip():
                        self._record_line(line, f"udp {addr[0]}:{addr[1]}")
            except socket.timeout:
                continue
            except OSError:
                break
        try:
            sock.close()
        except Exception:
            pass

    def _tcp_loop(self) -> None:
        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_sock.bind(("", self.tcp_port))
        self._tcp_sock.listen(5)
        self._tcp_sock.settimeout(1.0)
        log_event("info", f"TCP listening on {self.tcp_port}")
        while not self._stop.is_set():
            try:
                conn, addr = self._tcp_sock.accept()
                conn.settimeout(0.5)
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
                log_event("info", f"TCP client {addr} connected")
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, conn: socket.socket, addr) -> None:
        buf = ""
        try:
            while not self._stop.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", errors="ignore")
                if "\n" in buf:
                    parts = buf.split("\n")
                    buf = parts[-1]
                    for line in parts[:-1]:
                        if line.strip():
                            self._record_line(line, f"tcp {addr[0]}:{addr[1]}")
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        log_event("info", f"TCP client {addr} disconnected")


state_lock = threading.Lock()
rec = RecorderState()
events: List[Dict] = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _send(self, code: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/state":
            with state_lock:
                data = rec.to_dict()
                ev = list(events)
            self._send(200, json.dumps({"state": data, "events": ev, "ts": time.time()}).encode("utf-8"))
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            payload = {}
        if parsed.path == "/api/config":
            rec.configure(payload.get("udp_port"), payload.get("tcp_port"))
            self._send(200, b'{"ok":true}')
            return
        if parsed.path == "/api/start":
            rec.start()
            self._send(200, b'{"ok":true}')
            return
        if parsed.path == "/api/stop":
            rec.stop()
            self._send(200, b'{"ok":true}')
            return
        self._send(404, b"not found", "text/plain")


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GME NavRec (NMEA Recorder)</title>
  <style>
    :root { --bg:#0f172a; --card:rgba(255,255,255,0.06); --text:#e5e7eb; --muted:#94a3b8; --accent:#38bdf8; --ok:#4ade80; --err:#f87171; }
    * { box-sizing:border-box; }
    body { margin:0; padding:18px; background: radial-gradient(circle at 20% 20%, rgba(56,189,248,0.12), transparent 35%), radial-gradient(circle at 80% 0%, rgba(248,113,113,0.08), transparent 32%), var(--bg); color:var(--text); font-family:"Segoe UI",system-ui,-apple-system,sans-serif; }
    h1 { margin:0 0 10px; font-size:20px; letter-spacing:0.3px; }
    .grid { display:grid; grid-template-columns:320px 1fr; gap:16px; align-items:start; }
    .card { background:var(--card); border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:14px; }
    label { display:block; font-size:12px; color:var(--muted); margin-top:8px; }
    input { width:100%; padding:8px; border-radius:8px; border:1px solid rgba(255,255,255,0.1); background:rgba(0,0,0,0.2); color:var(--text); }
    button { margin-top:10px; padding:10px 12px; border:0; border-radius:8px; background:var(--accent); color:#04101f; font-weight:700; cursor:pointer; width:100%; }
    .row { display:flex; gap:10px; flex-wrap:wrap; }
    .vals { font-family:"Consolas","SFMono-Regular",monospace; font-size:13px; white-space:pre-wrap; }
    .badge { display:inline-block; padding:4px 8px; border-radius:999px; background:rgba(255,255,255,0.08); font-size:11px; }
    .muted { color:var(--muted); }
    .events { max-height:200px; overflow-y:auto; font-size:12px; }
    @media(max-width:960px){ .grid { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <h1>GME NavRec (UDP/TCP)</h1>
  <div class="grid">
    <div class="card">
      <div class="badge">Config</div>
      <label>UDP listen port</label>
      <input id="udp_port" type="number" value="10110">
      <label>TCP listen port</label>
      <input id="tcp_port" type="number" value="10111">
      <div class="row">
        <button style="background:#4ade80;color:#0a1c10;" onclick="startRec()">Start</button>
        <button style="background:#f87171;color:#2d0a0a;" onclick="stopRec()">Stop</button>
      </div>
      <button onclick="applyConfig()">Apply config</button>
      <div class="muted" style="margin-top:8px;">Log file: <span id="log_file">n/a</span></div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div class="badge">Stats</div>
        <div id="ts" class="muted" style="font-size:11px;"></div>
      </div>
      <div id="status" class="muted" style="margin-top:6px;">Stopped</div>
      <div class="muted" style="margin-top:6px;">Total: <span id="total">0</span> | OK: <span id="ok">0</span> | Bad: <span id="bad">0</span></div>
      <div class="badge" style="margin-top:10px;">Recent lines</div>
      <div id="lines" class="vals"></div>
    </div>
  </div>
  <div class="card" style="margin-top:16px;">
    <div class="badge">Recent events</div>
    <div id="events" class="events"></div>
    <div class="muted" style="margin-top:10px;font-size:12px;">Designed and built by Dan Gibson &amp; Codex 2025 (Gibson Marine Electrical LTD)</div>
  </div>
  <script>
    function esc(str){return (str||'').toString().replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]||c));}
    async function fetchJson(url){const r=await fetch(url); if(!r.ok) throw new Error(r.statusText); return r.json();}
    async function applyConfig(){
      const payload = {
        udp_port: Number(document.getElementById('udp_port').value),
        tcp_port: Number(document.getElementById('tcp_port').value),
      };
      await fetch('/api/config',{method:'POST',body:JSON.stringify(payload)});
      loadState();
    }
    async function startRec(){ await fetch('/api/start',{method:'POST'}); loadState(); }
    async function stopRec(){ await fetch('/api/stop',{method:'POST'}); loadState(); }
    async function loadState(){
      try{
        const r = await fetchJson('/api/state');
        const st = r.state;
        document.getElementById('udp_port').value = st.udp_port;
        document.getElementById('tcp_port').value = st.tcp_port;
        document.getElementById('status').innerHTML = st.running ? '<span class="ok">Running</span>' : '<span class="muted">Stopped</span>';
        document.getElementById('total').textContent = st.total;
        document.getElementById('ok').textContent = st.ok;
        document.getElementById('bad').textContent = st.bad;
        document.getElementById('log_file').textContent = st.log_file || 'n/a';
        document.getElementById('ts').textContent = 'Updated ' + new Date(r.ts*1000).toLocaleTimeString();
        const linesBox = document.getElementById('lines');
        linesBox.innerHTML = (st.last || []).slice().reverse().map(l=>{
          const cls = l.ok ? 'ok' : 'err';
          return `<div><span class="${cls}">${l.ok?'OK':'BAD'}</span> <span class="muted">${esc(l.src||'')}</span> ${esc(l.line||'')}</div>`;
        }).join('');
        const evbox = document.getElementById('events');
        evbox.innerHTML = (r.events||[]).slice().reverse().map(ev=>{
          const ts = new Date(ev.ts*1000).toLocaleTimeString();
          const cls = ev.level==='error'?'err':'muted';
          return `<div><span class="muted">${ts}</span> <span class="${cls}">${esc(ev.level)}</span> ${esc(ev.msg||'')}</div>`;
        }).join('');
      }catch(err){ console.error(err); }
    }
    function loop(){ loadState(); setTimeout(loop, 1200); }
    loop();
  </script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="GME NavRec (NMEA Recorder)")
    parser.add_argument("--port", type=int, help="HTTP port to listen on")
    parser.add_argument("--host", default=SERVER_HOST, help="Host/IP to bind (default 127.0.0.1)")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for port; use defaults/args")
    args = parser.parse_args()

    port = choose_port(SERVER_PORT, prompt=not args.no_prompt, arg_port=args.port)
    host = args.host

    server = HTTPServer((host, port), Handler)
    print(f"GME NavRec running on http://{host}:{port}")
    ips = get_local_ips()
    if ips:
        alts = " ".join(f"http://{ip}:{port}" for ip in ips)
        print(f"Also reachable (LAN): {alts}")
    else:
        print("No non-loopback IPs detected; using localhost.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        server.server_close()
        rec.stop()


if __name__ == "__main__":
    main()

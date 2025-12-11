#!/usr/bin/env python3
"""
NMEA GNSS simulator (HDT/HDG) with a local web UI.

- Serves http://127.0.0.1:8081
- Generates HDT and HDG sentences at a configurable rate
- Lets you set heading, step-per-tick (sweep), talker ID, and outputs
  to TCP server (clients connect and receive stream) and/or UDP target
- No external dependencies; pure stdlib for easy PyInstaller onefile builds.
"""

import argparse
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8081
EVENTS_MAX = 300


def checksum(sentence_body: str) -> str:
    csum = 0
    for ch in sentence_body:
        csum ^= ord(ch)
    return f"{csum:02X}"


def build_hdt(talker: str, heading: float) -> str:
    body = f"{talker}HDT,{heading:06.2f},T"
    return f"${body}*{checksum(body)}"


def build_hdg(talker: str, heading: float, variation: Optional[float]) -> str:
    var_field = ""
    if variation is not None:
        # Positive = East, Negative = West
        dir_char = "E" if variation >= 0 else "W"
        var_field = f",,,{abs(variation):05.1f},{dir_char}"
    else:
        var_field = ",,,,"
    body = f"{talker}HDG,{heading:06.2f}{var_field}"
    return f"${body}*{checksum(body)}"


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


class TcpBroadcaster:
    def __init__(self, port: int):
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.clients: List[socket.socket] = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", self.port))
        self.sock.listen(5)
        self.sock.settimeout(1.0)
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        log_event("info", f"TCP server listening on {self.port}")

    def _accept_loop(self) -> None:
        assert self.sock is not None
        while not self.stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
                conn.settimeout(0.5)
                with self.lock:
                    self.clients.append(conn)
                log_event("info", f"TCP client connected {addr}")
            except socket.timeout:
                continue
            except OSError:
                break
        self._close_all()

    def send(self, data: bytes) -> None:
        with self.lock:
            clients = list(self.clients)
        for c in clients:
            try:
                c.sendall(data)
            except Exception:
                try:
                    addr = c.getpeername()
                except Exception:
                    addr = "client"
                log_event("error", f"TCP send failed to {addr}; dropping client")
                with self.lock:
                    if c in self.clients:
                        self.clients.remove(c)
                try:
                    c.close()
                except Exception:
                    pass

    def stop(self) -> None:
        self.stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self._close_all()

    def _close_all(self) -> None:
        with self.lock:
            for c in self.clients:
                try:
                    c.close()
                except Exception:
                    pass
            self.clients.clear()


class UdpSender:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

    def start(self) -> None:
        if self.sock:
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        log_event("info", f"UDP target set to {self.host}:{self.port}")

    def send(self, data: bytes) -> None:
        if not self.sock:
            return
        try:
            self.sock.sendto(data, (self.host, self.port))
        except Exception as exc:
            log_event("error", f"UDP send failed: {exc}")

    def stop(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


class GeneratorState:
    def __init__(self):
        self.running = False
        self.heading = 0.0
        self.step = 0.0  # deg change per tick
        self.rate_hz = 1.0
        self.variation: Optional[float] = 0.0
        self.talker = "HE"
        self.tcp_port: Optional[int] = 20220
        self.udp_host: Optional[str] = "127.0.0.1"
        self.udp_port: Optional[int] = 10110
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._tcp: Optional[TcpBroadcaster] = None
        self._udp: Optional[UdpSender] = None
        self.last_sentences: List[str] = []

    def to_dict(self) -> Dict:
        return {
            "running": self.running,
            "heading": self.heading,
            "step": self.step,
            "rate_hz": self.rate_hz,
            "variation": self.variation,
            "talker": self.talker,
            "tcp_port": self.tcp_port,
            "udp_host": self.udp_host,
            "udp_port": self.udp_port,
            "last": self.last_sentences,
        }

    def configure(self, payload: Dict) -> None:
        self.heading = float(payload.get("heading", self.heading))
        self.step = float(payload.get("step", self.step))
        self.rate_hz = max(0.1, min(float(payload.get("rate_hz", self.rate_hz)), 20.0))
        self.talker = str(payload.get("talker", self.talker))[:2] or "HE"
        var = payload.get("variation", self.variation)
        self.variation = float(var) if var is not None else None
        self.tcp_port = int(payload["tcp_port"]) if payload.get("tcp_port") else None
        self.udp_host = payload.get("udp_host") or None
        self.udp_port = int(payload["udp_port"]) if payload.get("udp_port") else None
        self._ensure_sinks()

    def _ensure_sinks(self) -> None:
        # TCP
        if self.tcp_port:
            if not self._tcp or self._tcp.port != self.tcp_port:
                if self._tcp:
                    self._tcp.stop()
                self._tcp = TcpBroadcaster(self.tcp_port)
                self._tcp.start()
        else:
            if self._tcp:
                self._tcp.stop()
                self._tcp = None
        # UDP
        if self.udp_host and self.udp_port:
            if not self._udp or self._udp.host != self.udp_host or self._udp.port != self.udp_port:
                if self._udp:
                    self._udp.stop()
                self._udp = UdpSender(self.udp_host, self.udp_port)
                self._udp.start()
        else:
            if self._udp:
                self._udp.stop()
                self._udp = None

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self._ensure_sinks()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log_event("info", "Generator started")

    def stop(self) -> None:
        self.running = False
        self._stop.set()
        log_event("info", "Generator stopped")

    def _run(self) -> None:
        while not self._stop.is_set():
            t0 = time.time()
            sentences = self._build_sentences()
            payload = ("\r\n".join(sentences) + "\r\n").encode("ascii")
            if self._tcp:
                self._tcp.send(payload)
            if self._udp:
                self._udp.send(payload)
            with state_lock:
                self.last_sentences = sentences
            period = 1.0 / max(self.rate_hz, 0.1)
            dt = time.time() - t0
            sleep_for = max(0.0, period - dt)
            self.heading = (self.heading + self.step) % 360.0
            time.sleep(sleep_for)

    def _build_sentences(self) -> List[str]:
        h = self.heading % 360.0
        var = self.variation
        return [
            build_hdt(self.talker, h),
            build_hdg(self.talker, h, var),
        ]


state_lock = threading.Lock()
gen_state = GeneratorState()
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
                data = gen_state.to_dict()
            self._send(200, json.dumps(data).encode("utf-8"))
            return
        if parsed.path == "/api/events":
            qs = parse_qs(parsed.query or "")
            try:
                limit = int(qs.get("limit", ["200"])[0])
            except Exception:
                limit = 200
            with state_lock:
                out = events[-limit:]
            self._send(200, json.dumps({"events": out, "ts": time.time()}).encode("utf-8"))
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
            try:
                gen_state.configure(payload)
                self._send(200, b'{"ok":true}')
            except Exception as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"))
            return
        if parsed.path == "/api/start":
            gen_state.start()
            self._send(200, b'{"ok":true}')
            return
        if parsed.path == "/api/stop":
            gen_state.stop()
            self._send(200, b'{"ok":true}')
            return
        self._send(404, b"not found", "text/plain")


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GME NavSim (HDT/HDG)</title>
  <style>
    :root { --bg:#0f172a; --card:rgba(255,255,255,0.06); --text:#e5e7eb; --muted:#94a3b8; --accent:#38bdf8; --ok:#4ade80; --err:#f87171; }
    * { box-sizing:border-box; }
    body { margin:0; padding:18px; background: radial-gradient(circle at 20% 20%, rgba(56,189,248,0.12), transparent 35%), radial-gradient(circle at 80% 0%, rgba(248,113,113,0.08), transparent 32%), var(--bg); color:var(--text); font-family:"Segoe UI",system-ui,-apple-system,sans-serif; }
    h1 { margin:0 0 10px; font-size:20px; letter-spacing:0.3px; }
    .grid { display:grid; grid-template-columns:320px 1fr; gap:16px; align-items:start; }
    .card { background:var(--card); border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:14px; }
    label { display:block; font-size:12px; color:var(--muted); margin-top:8px; }
    input { width:100%; padding:8px; border-radius:8px; border:1px solid rgba(255,255,255,0.1); background:rgba(0,0,0,0.2); color:var(--text); }
    button { margin-top:12px; padding:10px 12px; border:0; border-radius:8px; background:var(--accent); color:#04101f; font-weight:700; cursor:pointer; width:100%; }
    .row { display:flex; gap:10px; flex-wrap:wrap; }
    .vals { font-family:"Consolas","SFMono-Regular",monospace; font-size:13px; }
    .badge { display:inline-block; padding:4px 8px; border-radius:999px; background:rgba(255,255,255,0.08); font-size:11px; }
    .muted { color:var(--muted); }
    .events { max-height:220px; overflow-y:auto; font-size:12px; }
    @media(max-width:960px){ .grid { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <h1>GME NavSim (HDT/HDG)</h1>
  <div class="grid">
    <div class="card">
      <div class="badge">Config</div>
      <label>Heading (deg)</label>
      <input id="heading" type="number" step="0.1" value="0.0">
      <label>Step per tick (deg) – e.g., 1.0 for sweep</label>
      <input id="step" type="number" step="0.1" value="0.0">
      <label>Rate (Hz)</label>
      <input id="rate" type="number" step="0.1" value="1.0">
      <label>Variation (deg, +E / -W, blank to omit)</label>
      <input id="variation" type="number" step="0.1" value="0.0">
      <label>Talker ID (2 chars, e.g., HE/GP/GN)</label>
      <input id="talker" maxlength="2" value="HE">
      <div class="row">
        <div style="flex:1;">
          <label>TCP output port (blank to disable)</label>
          <input id="tcp_port" type="number" value="20220">
        </div>
        <div style="flex:1;">
          <label>UDP target host</label>
          <input id="udp_host" value="127.0.0.1">
        </div>
        <div style="flex:1;">
          <label>UDP port (blank to disable)</label>
          <input id="udp_port" type="number" value="10110">
        </div>
      </div>
      <button onclick="applyConfig()">Apply config</button>
      <div class="row">
        <button style="background:#4ade80;color:#0a1c10;" onclick="startGen()">Start</button>
        <button style="background:#f87171;color:#2d0a0a;" onclick="stopGen()">Stop</button>
      </div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div class="badge">Live output</div>
        <div id="ts" class="muted" style="font-size:11px;"></div>
      </div>
      <div id="status" class="muted" style="margin-top:6px;">Waiting...</div>
      <div id="sentences" class="vals" style="margin-top:10px; white-space:pre-wrap;"></div>
      <div class="muted" style="margin-top:10px;">TCP clients: connect to the configured port to receive the stream.</div>
    </div>
  </div>
  <div class="card" style="margin-top:16px;">
    <div class="badge">Recent events</div>
    <div id="events" class="events"></div>
    <div class="muted" style="margin-top:10px;font-size:12px;">Designed and built by Dan Gibson &amp; Codex 2025 (Gibson Marine Electrical LTD)</div>
  </div>
  <script>
    function esc(str){return (str||'').toString().replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]||c));}
    async function fetchJson(url){const r=await fetch(url);if(!r.ok) throw new Error(r.statusText);return r.json();}
    async function applyConfig(){
      const variationRaw = document.getElementById('variation').value;
      const payload = {
        heading: Number(document.getElementById('heading').value),
        step: Number(document.getElementById('step').value),
        rate_hz: Number(document.getElementById('rate').value),
        variation: variationRaw === '' ? null : Number(variationRaw),
        talker: document.getElementById('talker').value.trim().slice(0,2) || 'HE',
        tcp_port: document.getElementById('tcp_port').value ? Number(document.getElementById('tcp_port').value) : null,
        udp_host: document.getElementById('udp_host').value.trim() || null,
        udp_port: document.getElementById('udp_port').value ? Number(document.getElementById('udp_port').value) : null,
      };
      await fetch('/api/config',{method:'POST',body:JSON.stringify(payload)});
      loadState();
    }
    async function startGen(){ await fetch('/api/start',{method:'POST'}); loadState(); }
    async function stopGen(){ await fetch('/api/stop',{method:'POST'}); loadState(); }
    async function loadState(){
      try{
        const st = await fetchJson('/api/state');
        document.getElementById('heading').value = st.heading.toFixed(1);
        document.getElementById('step').value = st.step.toFixed(1);
        document.getElementById('rate').value = st.rate_hz.toFixed(1);
        document.getElementById('talker').value = st.talker;
        document.getElementById('tcp_port').value = st.tcp_port || '';
        document.getElementById('udp_host').value = st.udp_host || '';
        document.getElementById('udp_port').value = st.udp_port || '';
        document.getElementById('variation').value = (st.variation === null || st.variation === undefined) ? '' : st.variation;
        document.getElementById('sentences').textContent = (st.last||[]).join('\\n');
        document.getElementById('status').innerHTML = st.running ? '<span class="ok">Running</span>' : '<span class="muted">Stopped</span>';
        document.getElementById('ts').textContent = 'Heading '+st.heading.toFixed(2)+'° | Rate '+st.rate_hz.toFixed(1)+' Hz';
      }catch(err){ console.error(err); }
    }
    async function loadEvents(){
      try{
        const data = await fetchJson('/api/events?limit=200');
        const box = document.getElementById('events');
        box.innerHTML = data.events.slice().reverse().map(ev=>{
          const ts=new Date(ev.ts*1000).toLocaleTimeString();
          const cls=ev.level==='error'?'err':'muted';
          return `<div><span class="muted">${ts}</span> <span class="${cls}">${esc(ev.level)}</span> ${esc(ev.msg||'')}</div>`;
        }).join('');
      }catch(err){ console.error(err); }
    }
    function loop(){ loadState(); loadEvents(); setTimeout(loop, 1500); }
    loop();
  </script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="GME NavSim (HDT/HDG)")
    parser.add_argument("--port", type=int, help="HTTP port to listen on")
    parser.add_argument("--host", default=SERVER_HOST, help="Host/IP to bind (default 127.0.0.1)")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for port; use defaults/args")
    args = parser.parse_args()

    port = choose_port(SERVER_PORT, prompt=not args.no_prompt, arg_port=args.port)
    host = args.host

    server = HTTPServer((host, port), Handler)
    print(f"GME NavSim (HDT/HDG) running on http://{host}:{port}")
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
        gen_state.stop()


if __name__ == "__main__":
    main()

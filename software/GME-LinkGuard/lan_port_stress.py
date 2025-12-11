#!/usr/bin/env python3
"""
LAN Port Stress/Health dashboard (portable, web UI).

- Serves http://127.0.0.1:8083
- Polls Windows adapter stats via PowerShell (Get-NetAdapter, Get-NetAdapterStatistics)
- Computes rolling Mbps (tx/rx), error deltas, and link state changes
- Optional ping target for basic latency sampling
- Event log for flaps/error increments

No external dependencies; pure stdlib. Intended for PyInstaller onefile build.
"""

import argparse
import json
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8083
EVENTS_MAX = 400


def powershell_json(cmd: str) -> Optional[object]:
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", cmd],
            encoding="utf-8",
            errors="ignore",
            timeout=4,
        )
        raw = raw.strip()
        if not raw:
            return None
        return json.loads(raw)
    except Exception:
        return None


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


def to_int(val, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        return default


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


class AdapterSnapshot:
    def __init__(self, name: str, now: float, stats: Dict, info: Dict):
        self.name = name
        self.ts = now
        self.rx_bytes = to_int(stats.get("ReceivedBytes", 0))
        self.tx_bytes = to_int(stats.get("SentBytes", 0))
        self.rx_errors = to_int(stats.get("ReceiveErrors", 0))
        self.tx_errors = to_int(stats.get("SendErrors", 0))
        self.rx_discards = to_int(stats.get("ReceivedDiscardedPackets", 0))
        self.tx_discards = to_int(stats.get("OutboundDiscardedPackets", 0))
        self.status = str(info.get("Status", "")).lower()
        self.linkspeed = str(info.get("LinkSpeed", ""))
        self.desc = info.get("InterfaceDescription", "")


class Monitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.snapshots: Dict[str, AdapterSnapshot] = {}
        self.events: List[Dict] = []
        self.increments: Dict[str, Dict[str, int]] = {}
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()

    def add_event(self, level: str, name: str, msg: str) -> None:
        entry = {"ts": time.time(), "level": level, "adapter": name, "msg": msg}
        with self.lock:
            self.events.append(entry)
            if len(self.events) > EVENTS_MAX:
                del self.events[: len(self.events) - EVENTS_MAX]

    def _run(self) -> None:
        while not self._stop.is_set():
            self._poll()
            time.sleep(1.0)

    def _poll(self) -> None:
        now = time.time()
        info = powershell_json(
            "Get-NetAdapter | Select-Object Name, Status, LinkSpeed, InterfaceDescription | ConvertTo-Json -Compress"
        )
        stats = powershell_json(
            "Get-NetAdapterStatistics | Select-Object Name, ReceivedBytes, SentBytes, ReceiveErrors, SendErrors, ReceivedDiscardedPackets, OutboundDiscardedPackets | ConvertTo-Json -Compress"
        )
        if not info or not stats:
            return
        if isinstance(info, dict):
            info_list = [info]
        else:
            info_list = info
        if isinstance(stats, dict):
            stats_list = [stats]
        else:
            stats_list = stats
        info_map = {i.get("Name"): i for i in info_list if i.get("Name")}
        stats_map = {s.get("Name"): s for s in stats_list if s.get("Name")}

        with self.lock:
            for name, s in stats_map.items():
                if name not in info_map:
                    continue
                snap = AdapterSnapshot(name, now, s, info_map[name])
                prev = self.snapshots.get(name)
                # Initialize increment bucket
                if name not in self.increments:
                    self.increments[name] = {
                        "rx_err": 0,
                        "tx_err": 0,
                        "rx_disc": 0,
                        "tx_disc": 0,
                    }
                if prev:
                    # Detect link change
                    if prev.status != snap.status:
                        self.add_event("info", name, f"Status {prev.status} -> {snap.status}")
                    # Error deltas
                    if snap.rx_errors > prev.rx_errors:
                        delta = snap.rx_errors - prev.rx_errors
                        self.increments[name]["rx_err"] += delta
                        self.add_event("warn", name, f"RX errors +{delta}")
                    if snap.tx_errors > prev.tx_errors:
                        delta = snap.tx_errors - prev.tx_errors
                        self.increments[name]["tx_err"] += delta
                        self.add_event("warn", name, f"TX errors +{delta}")
                    if snap.rx_discards > prev.rx_discards:
                        delta = snap.rx_discards - prev.rx_discards
                        self.increments[name]["rx_disc"] += delta
                        self.add_event("warn", name, f"RX discards +{delta}")
                    if snap.tx_discards > prev.tx_discards:
                        delta = snap.tx_discards - prev.tx_discards
                        self.increments[name]["tx_disc"] += delta
                        self.add_event("warn", name, f"TX discards +{delta}")
                self.snapshots[name] = snap

    def state(self) -> Dict:
        with self.lock:
            snaps = list(self.snapshots.values())
            events = list(self.events)
            prev_map = getattr(self, "_prev_map", {})
            curr_map = {s.name: s for s in snaps}
            self._prev_map = curr_map

        out = []
        for s in snaps:
            prev = prev_map.get(s.name)
            if prev and prev.ts != s.ts:
                dt = s.ts - prev.ts
                rx_mbps = ((s.rx_bytes - prev.rx_bytes) * 8 / 1_000_000) / dt if dt > 0 else 0.0
                tx_mbps = ((s.tx_bytes - prev.tx_bytes) * 8 / 1_000_000) / dt if dt > 0 else 0.0
            else:
                rx_mbps = tx_mbps = 0.0
            out.append(
                {
                    "name": s.name,
                    "status": s.status,
                    "linkspeed": s.linkspeed,
                    "desc": s.desc,
                    "rx_bytes": s.rx_bytes,
                    "tx_bytes": s.tx_bytes,
                    "rx_errors": s.rx_errors,
                    "tx_errors": s.tx_errors,
                    "rx_discards": s.rx_discards,
                    "tx_discards": s.tx_discards,
                    "rx_mbps": rx_mbps,
                    "tx_mbps": tx_mbps,
                    "ts": s.ts,
                    "inc_rx_err": self.increments.get(s.name, {}).get("rx_err", 0),
                    "inc_tx_err": self.increments.get(s.name, {}).get("tx_err", 0),
                    "inc_rx_disc": self.increments.get(s.name, {}).get("rx_disc", 0),
                    "inc_tx_disc": self.increments.get(s.name, {}).get("tx_disc", 0),
                }
            )
        return {"adapters": out, "ts": time.time(), "events": events}

    def reset(self) -> None:
        with self.lock:
            self.increments = {}
            self.events = []
            # Set prev map to current snapshots so deltas restart
            self._prev_map = dict(self.snapshots)
        self.add_event("info", "", "Reset counters and events")


monitor = Monitor()
monitor.start()


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
            self._send(200, json.dumps(monitor.state()).encode("utf-8"))
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
        if parsed.path == "/api/reset":
            monitor.reset()
            self._send(200, b'{"ok":true}')
            return
        self._send(404, b"not found", "text/plain")


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GME LinkGuard</title>
  <style>
    :root { --bg:#0f172a; --card:rgba(255,255,255,0.06); --text:#e5e7eb; --muted:#94a3b8; --accent:#38bdf8; --warn:#fbbf24; --err:#f87171; }
    * { box-sizing:border-box; }
    body { margin:0; padding:18px; background: radial-gradient(circle at 20% 20%, rgba(56,189,248,0.12), transparent 35%), radial-gradient(circle at 80% 0%, rgba(248,113,113,0.08), transparent 32%), var(--bg); color:var(--text); font-family:"Segoe UI",system-ui,-apple-system,sans-serif; }
    h1 { margin:0 0 10px; font-size:20px; letter-spacing:0.3px; }
    .wrap { display:grid; grid-template-columns: 1fr 320px; gap:16px; align-items:start; }
    .card { background:var(--card); border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:14px; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { padding:8px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.08); }
    th { color:var(--muted); font-size:11px; letter-spacing:0.5px; text-transform:uppercase; }
    .muted { color:var(--muted); }
    .ok { color:#4ade80; }
    .warn { color:var(--warn); }
    .err { color:var(--err); }
    .badge { display:inline-block; padding:4px 8px; border-radius:999px; background:rgba(255,255,255,0.08); font-size:11px; }
    .events { max-height:260px; overflow-y:auto; font-size:12px; }
    input { width:100%; padding:8px; border-radius:8px; border:1px solid rgba(255,255,255,0.1); background:rgba(0,0,0,0.2); color:var(--text); }
    button { margin-top:8px; padding:9px 12px; border:0; border-radius:8px; background:var(--accent); color:#04101f; font-weight:700; cursor:pointer; width:100%; }
    @media(max-width:960px){ .wrap { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <h1>GME LinkGuard (LAN Health)</h1>
  <div class="wrap">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div class="badge">Adapters</div>
        <div id="ts" class="muted" style="font-size:11px;"></div>
      </div>
      <div style="overflow-x:auto;">
      <table id="adapters">
        <thead><tr><th>Name</th><th>Status</th><th>Mbps Tx/Rx</th><th>Errors (Δ)</th><th>Discards (Δ)</th><th>Link</th></tr></thead>
        <tbody></tbody>
      </table>
      </div>
    </div>
    <div class="card">
      <div class="badge">Controls</div>
      <button onclick="resetAll()">Reset counters & events</button>
      <div class="badge" style="margin-top:12px;">Recent events</div>
      <div id="events" class="events"></div>
      <div class="muted" style="margin-top:10px;font-size:12px;">Designed and built by Dan Gibson &amp; Codex 2025 (Gibson Marine Electrical LTD)</div>
    </div>
  </div>
  <script>
    function esc(str){return (str||'').toString().replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]||c));}
    async function fetchJson(url){const r=await fetch(url); if(!r.ok) throw new Error(r.statusText); return r.json();}
    async function loadState(){
      try{
        const st = await fetchJson('/api/state');
        const tbody = document.querySelector('#adapters tbody');
        tbody.innerHTML='';
        st.adapters.forEach(a=>{
          const statusCls = a.status==='up'?'ok':'warn';
          const errs = `TX ${a.inc_tx_err} / RX ${a.inc_rx_err}`;
          const disc = `TX ${a.inc_tx_disc} / RX ${a.inc_rx_disc}`;
          const tr=document.createElement('tr');
          tr.innerHTML = `
            <td>${esc(a.name)}<div class="muted" style="font-size:11px;">${esc(a.desc||'')}</div></td>
            <td class="${statusCls}">${esc(a.status)}</td>
            <td>${a.tx_mbps.toFixed(2)} / ${a.rx_mbps.toFixed(2)}</td>
            <td class="warn">${esc(errs)}</td>
            <td class="warn">${esc(disc)}</td>
            <td class="muted">${esc(a.linkspeed||'')}</td>
          `;
          tbody.appendChild(tr);
        });
        document.getElementById('ts').textContent = 'Updated ' + new Date(st.ts*1000).toLocaleTimeString();
        const evbox = document.getElementById('events');
        evbox.innerHTML = st.events.slice().reverse().map(ev=>{
          const ts = new Date(ev.ts*1000).toLocaleTimeString();
          const cls = ev.level==='warn'?'warn':(ev.level==='error'?'err':'muted');
          return `<div><span class="muted">${ts}</span> <span class="${cls}">${esc(ev.level)}</span> <span class="muted">${esc(ev.adapter||'')}</span> ${esc(ev.msg||'')}</div>`;
        }).join('');
      }catch(err){ console.error(err); }
    }
    async function resetAll(){
      await fetch('/api/reset',{method:'POST'});
      loadState();
    }
    function loop(){ loadState(); setTimeout(loop, 1500); }
    loop();
  </script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="GME LinkGuard")
    parser.add_argument("--port", type=int, help="HTTP port to listen on")
    parser.add_argument("--host", default=SERVER_HOST, help="Host/IP to bind (default 127.0.0.1)")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for port; use defaults/args")
    args = parser.parse_args()

    port = choose_port(SERVER_PORT, prompt=not args.no_prompt, arg_port=args.port)
    host = args.host

    server = HTTPServer((host, port), Handler)
    print(f"GME LinkGuard running on http://{host}:{port}")
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
        monitor.stop()


if __name__ == "__main__":
    main()

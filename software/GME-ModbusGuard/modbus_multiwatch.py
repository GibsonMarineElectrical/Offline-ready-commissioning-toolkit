#!/usr/bin/env python3
"""
modbus_multiwatch.py
---------------------
Portable Modbus TCP poller with a built-in web UI.

- Poll multiple devices on user-defined IP/port (e.g., 502/503) and unit id
- Read holding registers (function 3) at configurable intervals
- Serve a local web dashboard (default http://127.0.0.1:8082) showing live values,
  errors, and a rolling event log
- Persist target list to config.json in this folder

No external dependencies; pure standard library for easy PyInstaller/onefile builds.
"""

import argparse
import json
import os
import random
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8082
EVENTS_MAX = 500

# Shared state
state_lock = threading.Lock()
targets: Dict[str, "TargetState"] = {}
events: List[Dict] = []


def log_event(level: str, target_id: str, message: str) -> None:
    entry = {
        "ts": time.time(),
        "level": level,
        "target": target_id,
        "msg": message,
    }
    with state_lock:
        events.append(entry)
        if len(events) > EVENTS_MAX:
            del events[: len(events) - EVENTS_MAX]


class TargetState:
    def __init__(
        self,
        target_id: str,
        host: str,
        port: int,
        unit_id: int,
        start: int,
        count: int,
        interval: float,
        name: Optional[str] = None,
    ):
        self.target_id = target_id
        self.name = name or target_id
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.start = start
        self.count = count
        self.interval = max(0.2, min(interval, 60.0))

        self.last_values: List[int] = []
        self.last_error: str = ""
        self.last_poll: float = 0.0
        self.success_count: int = 0
        self.error_count: int = 0
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_status_ok: Optional[bool] = None

    def to_dict(self) -> Dict:
        return {
            "id": self.target_id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "unit_id": self.unit_id,
            "start": self.start,
            "count": self.count,
            "interval": self.interval,
            "last_values": self.last_values,
            "last_error": self.last_error,
            "last_poll": self.last_poll,
            "success_count": self.success_count,
            "error_count": self.error_count,
        }

    def start_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            now = time.time()
            if now - self.last_poll >= self.interval:
                self._poll_once()
            time.sleep(0.05)

    def _poll_once(self) -> None:
        try:
            vals = read_holding_registers(
                self.host, self.port, self.unit_id, self.start, self.count
            )
            with state_lock:
                self.last_values = vals
                self.last_error = ""
                self.last_poll = time.time()
                self.success_count += 1
            if self._last_status_ok is False:
                log_event("info", self.target_id, "Recovered")
            self._last_status_ok = True
        except Exception as exc:  # noqa: BLE001
            with state_lock:
                self.last_error = str(exc)
                self.last_poll = time.time()
                self.error_count += 1
            if self._last_status_ok is not False:
                log_event("error", self.target_id, f"Poll failed: {exc}")
            self._last_status_ok = False


def read_holding_registers(
    host: str, port: int, unit_id: int, start: int, count: int, timeout: float = 2.0
) -> List[int]:
    """
    Minimal Modbus TCP function 3 (read holding registers).
    Returns a list of ints. Raises on errors/timeouts.
    """
    if count <= 0 or count > 120:
        raise ValueError("count must be 1..120")
    if start < 0 or start > 0xFFFF:
        raise ValueError("start must be 0..65535")
    if unit_id < 0 or unit_id > 247:
        raise ValueError("unit_id must be 0..247")

    tid = random.randint(0, 0xFFFF)
    # MBAP: transaction id (2), protocol (0), length (6), unit id (1)
    # PDU: function (3), start (2), count (2)
    req = bytearray()
    req += tid.to_bytes(2, "big")
    req += (0).to_bytes(2, "big")
    req += (6).to_bytes(2, "big")
    req.append(unit_id & 0xFF)
    req.append(3)
    req += start.to_bytes(2, "big")
    req += count.to_bytes(2, "big")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(req)
        # Response header: 7 bytes MBAP
        header = _recv_exact(sock, 7)
        if len(header) != 7:
            raise IOError("short response header")
        r_tid = int.from_bytes(header[0:2], "big")
        proto = int.from_bytes(header[2:4], "big")
        length = int.from_bytes(header[4:6], "big")
        r_uid = header[6]
        if proto != 0:
            raise IOError("invalid protocol id")
        if r_tid != tid:
            raise IOError("transaction id mismatch")
        if r_uid != (unit_id & 0xFF):
            raise IOError("unit id mismatch")
        pdu = _recv_exact(sock, length - 1)
        if not pdu or len(pdu) < 2:
            raise IOError("short PDU")
        func = pdu[0]
        if func == 0x83:
            code = pdu[1] if len(pdu) > 1 else -1
            raise IOError(f"device exception code {code}")
        if func != 3:
            raise IOError(f"unexpected function {func}")
        byte_count = pdu[1]
        if byte_count != 2 * count:
            raise IOError("byte count mismatch")
        data = pdu[2 : 2 + byte_count]
        vals = []
        for i in range(0, len(data), 2):
            vals.append(int.from_bytes(data[i : i + 2], "big"))
        return vals


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            break
        buf += chunk
        return bytes(buf)


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


def load_config() -> List[Dict]:
    if not os.path.isfile(CONFIG_PATH):
        return []
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return []


def save_config() -> None:
    with state_lock:
        data = [
            {
                "id": t.target_id,
                "name": t.name,
                "host": t.host,
                "port": t.port,
                "unit_id": t.unit_id,
                "start": t.start,
                "count": t.count,
                "interval": t.interval,
            }
            for t in targets.values()
        ]
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


def add_target(cfg: Dict) -> TargetState:
    target_id = cfg.get("id") or f"{cfg['host']}:{cfg['port']}/{cfg['unit_id']}/{cfg['start']}-{cfg['count']}"
    t = TargetState(
        target_id=target_id,
        name=cfg.get("name"),
        host=cfg["host"],
        port=int(cfg.get("port", 502)),
        unit_id=int(cfg.get("unit_id", 1)),
        start=int(cfg.get("start", 0)),
        count=int(cfg.get("count", 10)),
        interval=float(cfg.get("interval", 1.0)),
    )
    with state_lock:
        targets[target_id] = t
    t.start_thread()
    log_event("info", target_id, f"Added target {t.host}:{t.port} unit {t.unit_id} start {t.start} count {t.count}")
    save_config()
    return t


def remove_target(target_id: str) -> bool:
    with state_lock:
        t = targets.pop(target_id, None)
    if t:
        t.stop()
        log_event("info", target_id, "Removed target")
        save_config()
        return True
    return False


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
        if parsed.path == "/api/targets":
            with state_lock:
                data = [t.to_dict() for t in targets.values()]
            self._send(200, json.dumps({"targets": data, "ts": time.time()}).encode("utf-8"))
            return
        if parsed.path == "/api/events":
            qs = parse_qs(parsed.query or "")
            try:
                limit = int(qs.get("limit", ["200"])[0])
            except Exception:  # noqa: BLE001
                limit = 200
            with state_lock:
                out = events[-limit:]
            self._send(200, json.dumps({"events": out, "ts": time.time()}).encode("utf-8"))
            return
        if parsed.path == "/api/ping":
            self._send(200, b'{"ok":true}')
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:  # noqa: BLE001
            payload = {}

        if parsed.path == "/api/targets":
            required = ["host"]
            if not all(k in payload for k in required):
                self._send(400, b'{"error":"host required"}')
                return
            try:
                t = add_target(payload)
            except Exception as exc:  # noqa: BLE001
                self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"))
                return
            self._send(200, json.dumps({"ok": True, "id": t.target_id}).encode("utf-8"))
            return

        if parsed.path == "/api/remove":
            target_id = payload.get("id") or ""
            if not target_id:
                self._send(400, b'{"error":"id required"}')
                return
            ok = remove_target(target_id)
            if ok:
                self._send(200, b'{"ok":true}')
            else:
                self._send(404, b'{"error":"not found"}')
            return

        self._send(404, b"not found", "text/plain")


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GME ModGuard (Modbus)</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: rgba(255,255,255,0.06);
      --text: #e5e7eb;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --error: #f87171;
      --ok: #4ade80;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 18px;
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 20% 20%, rgba(56,189,248,0.12), transparent 35%),
                  radial-gradient(circle at 80% 0%, rgba(248,113,113,0.08), transparent 32%),
                  var(--bg);
      color: var(--text);
    }
    h1 { margin: 0 0 12px; font-size: 20px; letter-spacing: 0.3px; }
    .wrap { display: grid; grid-template-columns: 320px 1fr; gap: 16px; align-items: start; }
    .card { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 14px; }
    label { display: block; font-size: 12px; color: var(--muted); margin-top: 8px; }
    input { width: 100%; padding: 8px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); background: rgba(0,0,0,0.2); color: var(--text); }
    button { margin-top: 12px; padding: 10px 12px; border: 0; border-radius: 8px; background: var(--accent); color: #04101f; font-weight: 700; cursor: pointer; width: 100%; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.08); }
    th { color: var(--muted); font-size: 11px; letter-spacing: 0.5px; text-transform: uppercase; }
    .muted { color: var(--muted); }
    .err { color: var(--error); }
    .ok { color: var(--ok); }
    .vals { font-family: "Consolas","SFMono-Regular",monospace; }
    .events { max-height: 220px; overflow-y: auto; font-size: 12px; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 999px; background: rgba(255,255,255,0.08); font-size: 11px; }
    @media (max-width: 960px) { .wrap { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>GME ModGuard (Modbus)</h1>
  <div class="wrap">
    <div class="card">
      <div class="badge">Add target</div>
      <label>Friendly name (optional)</label>
      <input id="name" placeholder="Fuel cell A" />
      <label>IP / Host</label>
      <input id="host" placeholder="192.168.0.10" />
      <label>Port</label>
      <input id="port" type="number" value="502" />
      <label>Unit ID</label>
      <input id="unit" type="number" value="1" />
      <label>Start register</label>
      <input id="start" type="number" value="0" />
      <label>Count</label>
      <input id="count" type="number" value="10" />
      <label>Poll interval (seconds)</label>
      <input id="interval" type="number" step="0.1" value="1.0" />
      <button onclick="addTarget()">Add / Update</button>
      <div style="margin-top:12px;font-size:12px;color:var(--muted);">Uses Modbus TCP function 3 (holding registers). Polls continuously.</div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div class="badge">Targets</div>
        <div id="ts" class="muted" style="font-size:11px;"></div>
      </div>
      <div style="overflow-x:auto;">
      <table id="targets">
        <thead>
          <tr><th>Name</th><th>Host</th><th>Last values</th><th>Status</th><th></th></tr>
        </thead>
        <tbody></tbody>
      </table>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:16px;">
    <div class="badge">Recent events</div>
    <div id="events" class="events"></div>
    <div class="muted" style="margin-top:10px;font-size:12px;">Designed and built by Dan Gibson &amp; Codex 2025 (Gibson Marine Electrical LTD)</div>
  </div>
  <script>
    async function fetchJson(url) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(res.statusText);
      return res.json();
    }
    function esc(str){return (str||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]||c));}
    async function loadTargets(){
      try {
        const data = await fetchJson('/api/targets');
        const tbody = document.querySelector('#targets tbody');
        tbody.innerHTML='';
        data.targets.forEach(t=>{
          const tr=document.createElement('tr');
          const vals = (t.last_values||[]).slice(0,12).map(v=>String(v)).join(', ');
          const age = data.ts - (t.last_poll||0);
          const healthy = (!t.last_error) && age<10;
          tr.innerHTML = `
            <td>${esc(t.name||t.id)}</td>
            <td class="muted">${esc(t.host)}:${t.port} u${t.unit_id} [${t.start}:${t.count}]</td>
            <td class="vals">${esc(vals)}</td>
            <td>${healthy ? '<span class="ok">OK</span>' : '<span class="err">Error</span>'} <span class="muted">(${t.success_count}/${t.error_count})</span><div class="muted" style="max-width:240px;">${esc(t.last_error||'')}</div></td>
            <td><button style="padding:6px 8px;" onclick="removeTarget('${t.id}')">Remove</button></td>
          `;
          tbody.appendChild(tr);
        });
        document.getElementById('ts').textContent = 'Updated ' + new Date(data.ts*1000).toLocaleTimeString();
      } catch(err){
        console.error(err);
      }
    }
    async function loadEvents(){
      try{
        const data = await fetchJson('/api/events?limit=200');
        const box = document.getElementById('events');
        box.innerHTML = data.events.slice().reverse().map(ev=>{
          const ts = new Date(ev.ts*1000).toLocaleTimeString();
          const cls = ev.level === 'error' ? 'err' : 'muted';
          return `<div><span class="muted">${ts}</span> <span class="${cls}">${esc(ev.level)}</span> <span class="muted">${esc(ev.target||'')}</span> ${esc(ev.msg||'')}</div>`;
        }).join('');
      }catch(err){ console.error(err); }
    }
    async function addTarget(){
      const payload = {
        name: document.getElementById('name').value.trim() || undefined,
        host: document.getElementById('host').value.trim(),
        port: Number(document.getElementById('port').value),
        unit_id: Number(document.getElementById('unit').value),
        start: Number(document.getElementById('start').value),
        count: Number(document.getElementById('count').value),
        interval: Number(document.getElementById('interval').value),
      };
      if(!payload.host){ alert('Host required'); return; }
      try{
        const res = await fetch('/api/targets',{method:'POST',body:JSON.stringify(payload)});
        if(!res.ok){ const t=await res.text(); alert('Error: '+t); return; }
        document.getElementById('host').value='';
        loadTargets();
      }catch(err){ alert(err); }
    }
    async function removeTarget(id){
      if(!confirm('Remove target '+id+'?')) return;
      await fetch('/api/remove',{method:'POST',body:JSON.stringify({id})});
      loadTargets();
    }
    function loop(){
      loadTargets(); loadEvents();
      setTimeout(loop, 2000);
    }
    loop();
  </script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="GME ModGuard (Modbus)")
    parser.add_argument("--port", type=int, help="HTTP port to listen on")
    parser.add_argument("--host", default=SERVER_HOST, help="Host/IP to bind (default 127.0.0.1)")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for port; use defaults/args")
    args = parser.parse_args()

    port = choose_port(SERVER_PORT, prompt=not args.no_prompt, arg_port=args.port)
    host = args.host

    # Load persisted targets
    for cfg in load_config():
        try:
            add_target(cfg)
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to load target {cfg}: {exc}")

    server = HTTPServer((host, port), Handler)
    print(f"GME ModGuard (Modbus) running on http://{host}:{port}")
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
        with state_lock:
            for t in targets.values():
                t.stop()


if __name__ == "__main__":
    main()
